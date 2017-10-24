#[macro_use]
extern crate futures;
extern crate u2f_core;
extern crate u2fhid_transport_header;
extern crate byteorder;

mod send_all;

use std::cmp;
use std::collections::HashSet;
use std::io;
use std::mem;
use std::boxed::Box;

use byteorder::{BigEndian, WriteBytesExt};
use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream, stream};

use u2f_core::{Request};
use send_all::SendAll;
use u2fhid_transport_header as header;

type ChannelId = u32;
type U2FHIDProtocolVersionId = u8;

const INITIAL_PACKET_DATA_MAX_LEN: usize = header::HID_RPT_SIZE as usize - 7;
const CONTINUATION_PACKET_DATA_MAX_LEN: usize = header::HID_RPT_SIZE as usize - 5;

enum ErrorCode {
    ChannelBusy,
    InvalidSequence,
}

enum Command {
    Msg,
    Ping,
    Init,
    Error,
    Wink,
    Lock,
    Vendor { identifier: u8 },
}

enum RequestMessage {
    EncapsulatedRequest { data: Vec<u8> },
    Init { nonce: [u8; 8] },
    Ping { data: Vec<u8> },
    Wink,
    Lock { lock_time: u8 }, // Lock time in seconds 0..10. A value of 0 immediately releases the lock
}

enum ResponseMessage {
    EncapsulatedResponse { data: Vec<u8> },
    Init {
        nonce: [u8; 8],
        channel_id: ChannelId,
        u2fhid_protocol_version: U2FHIDProtocolVersionId,
        major_device_version_number: u8,
        minor_device_version_number: u8,
        build_device_version_number: u8,
        capabilities: u8,
    },
    Ping { data: Vec<u8> },
    Error { code: ErrorCode },
    Wink,
}

impl ResponseMessage {
    fn to_packets(self, channel_id: ChannelId) -> Vec<Packet> {
        match self {
            ResponseMessage::EncapsulatedResponse { data } => {
                encode_response(channel_id, Command::Msg, &data)
            },
            ResponseMessage::Init {
                nonce,
                channel_id,
                u2fhid_protocol_version,
                major_device_version_number,
                minor_device_version_number,
                build_device_version_number,
                capabilities,
            } => {
                let mut data = Vec::with_capacity(17);
                data.extend_from_slice(&nonce);
                data.write_u32::<BigEndian>(channel_id).unwrap();
                data.push(u2fhid_protocol_version);
                data.push(major_device_version_number);
                data.push(minor_device_version_number);
                data.push(build_device_version_number);
                data.push(capabilities);
                assert_eq!(data.len(), 17);
                encode_response(channel_id, Command::Init, &data)
            }
            ResponseMessage::Ping {data} => {
                encode_response(channel_id, Command::Ping, &data)
            }
            ResponseMessage::Error {code} => {
                let error_code_byte = match code {
                    ErrorCode::ChannelBusy => header::ERR_CHANNEL_BUSY,
                    ErrorCode::InvalidSequence => header::ERR_INVALID_SEQ,
                } as u8;
                let data = vec![error_code_byte];
                encode_response(channel_id, Command::Error, &data)
            }
            ResponseMessage::Wink => {
                encode_response(channel_id, Command::Wink, &[])
            }
        }
    }
}

enum Packet {
    Initialization {
        channel_id: ChannelId,
        command: Command,
        payload_len: usize,
        data: Vec<u8>,
    },
    Continuation {
        channel_id: ChannelId,
        sequence_number: u8,
        data: Vec<u8>,
    },
}

enum State {
    Idle,
    Receiving {
        buffer: Vec<u8>,
        command: Command,
        next_sequence_number: u8,
        payload_len: usize,
        receive_channel_id: ChannelId,
        // TODO timeout
    },
    Processing { channel_id: ChannelId },
    Responding,
}

enum StreamState<S: Sink + Stream, E: Sized> {
    Unknown,
    Ready(S),
    SinkSending(SendAll<S, futures::stream::IterOk<std::vec::IntoIter<Packet>, E>>),
    SinkError(S, E),
    StreamSending(SendAll<S, futures::stream::IterOk<std::vec::IntoIter<Packet>, E>>),
    StreamError(S, E),
}

impl<S: Sink + Stream, E> StreamState<S, E> {
    fn take(&mut self) -> StreamState<S, E> {
        mem::replace(self, StreamState::Unknown)
    }
}

struct U2FHID<S: Sink + Stream, E> {
    channels: HashSet<ChannelId>,
    state: State,
    stream_state: StreamState<S, E>,
}

impl<S: Sink<SinkItem = Packet, SinkError = E> + Stream<Item = Packet, Error = E>, E> U2FHID<S, E> {
    fn new(inner: S) -> U2FHID<S, E> {
        U2FHID {
            channels: HashSet::new(),
            state: State::Idle,
            stream_state: StreamState::Ready(inner),
        }
    }

    fn handle_packet(&mut self, packet: Packet, stream: S) -> Poll<Option<RequestMessage>, E> {
        match self.state {
            State::Idle => {
                match packet {
                    Packet::Initialization {
                        channel_id,
                        data,
                        payload_len,
                        command,
                        ..
                    } => {
                        if data.len() >= payload_len {
                            let message = decode_request_message(&command, &data[0..payload_len]).unwrap();
                            // TODO check if internal command or should be passed on
                            Ok(Async::Ready(Some(message)))
                        } else {
                            self.state = State::Receiving {
                                buffer: data.to_vec(),
                                command: command,
                                next_sequence_number: 0,
                                payload_len: payload_len,
                                receive_channel_id: channel_id,
                            };
                            Ok(Async::NotReady)
                        }
                    }
                    Packet::Continuation { channel_id, .. } => {
                        let s = Self::send_error(stream, channel_id, ErrorCode::InvalidSequence);
                        self.stream_state = StreamState::StreamSending(s);
                        Ok(Async::NotReady)
                    }
                }
            }
            State::Receiving {
                receive_channel_id,
                ref mut next_sequence_number,
                payload_len,
                ref mut buffer,
                ref command,
            } => {
                match packet {
                    Packet::Initialization { channel_id, .. } => {
                        let s = Self::send_error(stream, channel_id, ErrorCode::ChannelBusy);
                        self.stream_state = StreamState::StreamSending(s);
                        Ok(Async::NotReady)
                    }
                    Packet::Continuation {
                        channel_id,
                        sequence_number,
                        data,
                    } => {
                        if receive_channel_id != channel_id {
                            let s = Self::send_error(stream, channel_id, ErrorCode::ChannelBusy);
                            self.stream_state = StreamState::StreamSending(s);
                            Ok(Async::NotReady)
                        } else if sequence_number != *next_sequence_number {
                            let s =
                                Self::send_error(stream, channel_id, ErrorCode::InvalidSequence);
                            self.stream_state = StreamState::StreamSending(s);
                            Ok(Async::NotReady)
                        } else {
                            *next_sequence_number += 1;
                            buffer.extend_from_slice(&data);
                            if buffer.len() >= payload_len {
                                // TODO better than unwrap
                                let message = decode_request_message(&command, &buffer[0..payload_len]).unwrap();
                                // TODO check if internal command or should be passed on
                                Ok(Async::Ready(Some(message)))
                            } else {
                                Ok(Async::NotReady)
                            }
                        }
                    }
                }
            }
            State::Processing { .. } => {
                match packet {
                    Packet::Initialization { channel_id, .. } => {
                        let s = Self::send_error(stream, channel_id, ErrorCode::ChannelBusy);
                        self.stream_state = StreamState::StreamSending(s);
                        Ok(Async::NotReady)
                    }
                    Packet::Continuation { channel_id, .. } => {
                        let s = Self::send_error(stream, channel_id, ErrorCode::ChannelBusy);
                        self.stream_state = StreamState::StreamSending(s);
                        Ok(Async::NotReady)
                    }
                }
            }
            State::Responding => {
                match packet {
                    Packet::Initialization { channel_id, .. } => {
                        let s = Self::send_error(stream, channel_id, ErrorCode::ChannelBusy);
                        self.stream_state = StreamState::StreamSending(s);
                        Ok(Async::NotReady)
                    }
                    Packet::Continuation { channel_id, .. } => {
                        let s = Self::send_error(stream, channel_id, ErrorCode::ChannelBusy);
                        self.stream_state = StreamState::StreamSending(s);
                        Ok(Async::NotReady)
                    }
                }
            }
        }
    }

    fn handle_request_message(&mut self, message: RequestMessage, stream: S, channel_id: ChannelId) -> Poll<Option<Request>, E> {
        match message {
            RequestMessage::EncapsulatedRequest { data } => {
                let request = Request::decode(&data).unwrap();
                Ok(Async::Ready(Some(request)))
            },
            RequestMessage::Init { nonce } => {
                // TODO
                Ok(Async::NotReady)
            },
            RequestMessage::Ping { data } => {
                Self::send_response_message(ResponseMessage::Ping {
                    data: data,
                }, stream, channel_id);
                Ok(Async::NotReady)
            },
            RequestMessage::Wink => {
                Ok(Async::Ready(Some(Request::Wink)))
            },
            RequestMessage::Lock { lock_time } => {
                if lock_time == 0 {
                    self.release_lock();
                } else {
                    // TODO enforce range of 1-10
                }
                Ok(Async::NotReady)
            },
        }
    }

    fn release_lock(&mut self) {}

    fn try_take_inner_sink(&mut self) -> Poll<S, E> {
        match self.stream_state.take() {
            StreamState::Ready(inner) => Ok(Async::Ready(inner)),
            StreamState::SinkError(inner, error) => {
                self.stream_state = StreamState::Ready(inner);
                Err(error)
            }
            StreamState::SinkSending(mut future) => {
                match future.poll() {
                    Ok(Async::NotReady) => Ok(Async::NotReady),
                    Ok(Async::Ready((inner, _))) => Ok(Async::Ready(inner)),
                    Err(error) => Err(error),
                }
            }
            StreamState::StreamError(_, _) => Ok(Async::NotReady),
            StreamState::StreamSending(_) => Ok(Async::NotReady),
            StreamState::Unknown => panic!(),
        }
    }

    fn try_take_inner_stream(&mut self) -> Poll<S, E> {
        match self.stream_state.take() {
            StreamState::Ready(inner) => Ok(Async::Ready(inner)),
            StreamState::SinkError(_, _) => Ok(Async::NotReady),
            StreamState::SinkSending(_) => Ok(Async::NotReady),
            StreamState::StreamError(inner, error) => {
                self.stream_state = StreamState::Ready(inner);
                Err(error)
            }
            StreamState::StreamSending(mut future) => {
                match future.poll() {
                    Ok(Async::NotReady) => Ok(Async::NotReady),
                    Ok(Async::Ready((inner, _))) => Ok(Async::Ready(inner)),
                    Err(error) => Err(error),
                }
            }
            StreamState::Unknown => panic!(),
        }
    }

    fn send_error(
        stream: S,
        channel_id: ChannelId,
        error_code: ErrorCode,
    ) -> SendAll<S, futures::stream::IterOk<std::vec::IntoIter<Packet>, E>> {
        Self::send_response_message(ResponseMessage::Error {
            code: error_code
        }, stream, channel_id)
    }

    fn send_response_message(message: ResponseMessage, stream: S, channel_id: ChannelId) -> SendAll<S, futures::stream::IterOk<std::vec::IntoIter<Packet>, E>> {
        let packets = message.to_packets(channel_id);
        send_all::new(stream, stream::iter_ok(packets))
    }
}

impl<
    S: Sink<SinkItem = Packet, SinkError = E> + Stream<Item = Packet, Error = E> + 'static,
    E: 'static,
> Sink for U2FHID<S, E> {
    type SinkItem = ResponseMessage;
    type SinkError = S::SinkError;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        let sink = match self.try_take_inner_sink()? {
            Async::Ready(inner) => inner,
            Async::NotReady => return Ok(AsyncSink::NotReady(item)),
        };
        if let State::Processing { channel_id, .. } = self.state {
            self.state = State::Responding;
            let packets = encode_response_message(channel_id, item).unwrap();
            let s = send_all::new(sink, stream::iter_ok(packets));
            self.stream_state = StreamState::SinkSending(s);
            Ok(AsyncSink::Ready)
        } else {
            Ok(AsyncSink::NotReady(item))
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        let mut inner = match self.try_take_inner_sink()? {
            Async::Ready(inner) => inner,
            Async::NotReady => return Ok(Async::NotReady),
        };
        inner.poll_complete()
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        let mut inner = match self.try_take_inner_sink()? {
            Async::Ready(inner) => inner,
            Async::NotReady => return Ok(Async::NotReady),
        };
        inner.close()
    }
}

impl<S: Stream<Item = Packet, Error = E> + Sink<SinkItem = Packet, SinkError = E>, E> Stream
    for U2FHID<S, E> {
    type Item = RequestMessage;
    type Error = <S as futures::Stream>::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut stream = try_ready!(self.try_take_inner_stream());
        match stream.poll() {
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Ok(Async::Ready(Some(packet))) => self.handle_packet(packet, stream),
            Ok(Async::Ready(None)) => Ok(Async::Ready(None)),
            Err(error) => Err(error),
        }
    }
}

fn decode_request_message(command: &Command, data: &[u8]) -> Result<RequestMessage, ()> {
    match command {
        &Command::Msg => Ok(RequestMessage::EncapsulatedRequest { data: data.to_vec() }),
        &Command::Ping => Ok(RequestMessage::Ping { data: data.to_vec() }),
        &Command::Init => {
            if data.len() != 8 {
                Err(())
            } else {
                let mut nonce = [0u8; 8];
                nonce.copy_from_slice(&data[0..7]);
                Ok(RequestMessage::Init { nonce: nonce })
            }
        }
        &Command::Wink => Ok(RequestMessage::Wink),
        &Command::Lock => {
            if data.len() != 1 {
                Err(())
            } else {
                Ok(RequestMessage::Lock { lock_time: data[0] })
            }
        }
        &Command::Error => Err(()),
        &Command::Vendor { .. } => Err(()),
    }
}

fn encode_response_message(
    channel_id: ChannelId,
    response_message: ResponseMessage,
) -> Result<Vec<Packet>, ()> {
    Ok(response_message.to_packets(channel_id))
}

fn encode_response(channel_id: ChannelId, command: Command, data: &[u8]) -> Vec<Packet> {
    let mut packets: Vec<Packet> = Vec::new();
    let split_index = cmp::min(data.len(), INITIAL_PACKET_DATA_MAX_LEN);
    let (initial, remaining) = data.split_at(split_index);
    packets.push(Packet::Initialization {
        channel_id: channel_id,
        command: command,
        payload_len: data.len(),
        data: initial.to_vec(),
    });
    for (i, chunk) in remaining
        .chunks(CONTINUATION_PACKET_DATA_MAX_LEN)
        .enumerate()
    {
        packets.push(Packet::Continuation {
            channel_id: channel_id,
            sequence_number: i as u8,
            data: chunk.to_vec(),
        });
    }
    packets
}
