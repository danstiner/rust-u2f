use std::mem;

use definitions::*;
use u2f_core::Request;

#[derive(Debug)]
pub enum Output {
    Request(Request),
    ResponseMessage(ResponseMessage, ChannelId),
}

struct ReceiveState {
    buffer: Vec<u8>,
    command: Command,
    next_sequence_number: u8,
    payload_len: usize,
    receive_channel_id: ChannelId,
    // TODO timeout
}

enum State {
    Idle,
    Receive(ReceiveState),
    Processing,
    Unknown,
}

impl State {
    fn take(&mut self) -> State {
        mem::replace(self, State::Unknown)
    }
}

const BROADCAST_CHANNEL_ID: ChannelId = 0xffffffff;
const MAX_CHANNEL_ID: ChannelId = 5;
const MIN_CHANNEL_ID: ChannelId = 1;

#[derive(Debug)]
struct Channels {
    next_allocation: ChannelId,
}

impl Channels {
    fn new() -> Channels {
        Channels { next_allocation: MIN_CHANNEL_ID }
    }

    fn allocate(&mut self) -> Result<ChannelId, ()> {
        if self.next_allocation > MAX_CHANNEL_ID {
            Err(())
        } else {
            let allocation = self.next_allocation;
            self.next_allocation += 1;
            Ok(allocation)
        }
    }

    fn is_valid(&self, channel_id: ChannelId) -> bool {
        let is_broadcast = channel_id == BROADCAST_CHANNEL_ID;
        let is_in_allocated_range = channel_id >= MIN_CHANNEL_ID &&
            channel_id < self.next_allocation;
        is_broadcast || is_in_allocated_range
    }
}

struct StateTransition {
    new_state: State,
    output: Option<Output>,
}

pub struct StateMachine {
    channels: Channels,
    state: State,
    // TODO lock
}

impl StateMachine {
    pub fn new() -> StateMachine {
        StateMachine {
            channels: Channels::new(),
            state: State::Idle,
        }
    }

    pub fn accept_packet(&mut self, packet: Packet) -> Result<Option<Output>, ()> {
        let packet_channel_id = packet.channel_id();
        if !self.channels.is_valid(packet_channel_id) {
            return Ok(Some(Output::ResponseMessage(
                ResponseMessage::Error { code: ErrorCode::InvalidChannel },
                packet_channel_id,
            )));
        }
        let transition: StateTransition = match (self.state.take(), packet) {
            (State::Idle,
             Packet::Initialization {
                 channel_id,
                 data,
                 payload_len,
                 command,
             }) => {
                if data.len() >= payload_len {
                    let message = RequestMessage::decode(&command, &data[0..payload_len]).unwrap();
                    StateTransition {
                        new_state: State::Idle, // TODO decide on next state
                        output: self.handle_request_message(message, channel_id)?,
                    }
                } else {
                    StateTransition {
                        new_state: State::Receive(ReceiveState {
                            buffer: data.to_vec(),
                            command: command,
                            next_sequence_number: 0,
                            payload_len: payload_len,
                            receive_channel_id: channel_id,
                        }),
                        output: None,
                    }
                }
            }
            (state @ State::Idle, Packet::Continuation { .. }) => {
                // TODO info!("Out of order continuation packet, ignoring.");
                StateTransition {
                    new_state: state,
                    output: None,
                }
            }
            (State::Receive(receive), Packet::Initialization { channel_id, .. }) => {
                if channel_id != receive.receive_channel_id {
                    StateTransition {
                        new_state: State::Receive(receive),
                        output: Some(Output::ResponseMessage(
                            ResponseMessage::Error { code: ErrorCode::ChannelBusy },
                            channel_id,
                        )),
                    }
                } else {
                    StateTransition {
                        new_state: State::Idle,
                        output: Some(Output::ResponseMessage(
                            ResponseMessage::Error {
                                code: ErrorCode::InvalidMessageSequencing,
                            },
                            channel_id,
                        )),
                    }
                }
            }
            (State::Receive(mut receive),
             Packet::Continuation {
                 channel_id,
                 sequence_number,
                 data,
             }) => {
                if channel_id != receive.receive_channel_id {
                    StateTransition {
                        new_state: State::Receive(receive),
                        output: Some(Output::ResponseMessage(
                            ResponseMessage::Error { code: ErrorCode::ChannelBusy },
                            channel_id,
                        )),
                    }
                } else if sequence_number != receive.next_sequence_number {
                    StateTransition {
                        new_state: State::Idle,
                        output: Some(Output::ResponseMessage(
                            ResponseMessage::Error {
                                code: ErrorCode::InvalidMessageSequencing,
                            },
                            channel_id,
                        )),
                    }
                } else {
                    receive.next_sequence_number += 1;
                    receive.buffer.extend_from_slice(&data);
                    if receive.buffer.len() >= receive.payload_len {
                        // TODO better than unwrap
                        let message = RequestMessage::decode(
                            &receive.command,
                            &receive.buffer[0..receive.payload_len],
                        ).unwrap();
                        StateTransition {
                            new_state: State::Processing, // TODO decide on next state
                            output: self.handle_request_message(message, channel_id)?,
                        }
                    } else {
                        StateTransition {
                            new_state: State::Receive(receive),
                            output: None,
                        }
                    }
                }
            }
            (state @ State::Processing, _) => StateTransition {
                new_state: state,
                output: Some(Output::ResponseMessage(
                    ResponseMessage::Error { code: ErrorCode::ChannelBusy },
                    packet_channel_id,
                )),
            },
            (State::Unknown, _) => panic!(),
        };
        self.state = transition.new_state;
        Ok(transition.output)
    }

    pub fn transition_to_responding(&mut self) -> Option<ChannelId> {
        None // TODO
    }

    fn allocate_channel(&mut self) -> Result<ChannelId, ()> {
        self.channels.allocate()
    }

    fn handle_request_message(
        &mut self,
        message: RequestMessage,
        channel_id: ChannelId,
    ) -> Result<Option<Output>, ()> {
        match message {
            RequestMessage::EncapsulatedRequest { data } => {
                Ok(Some(Output::Request(Request::decode(&data).unwrap()))) // TODO no unwrap
            }
            RequestMessage::Init { nonce } => {
                // TODO Check what channnel message came in on
                // TODO check unwrap
                let new_channel_id = self.allocate_channel().unwrap();
                Ok(Some(Output::ResponseMessage(
                    ResponseMessage::Init {
                        nonce,
                        channel_id: new_channel_id,
                        u2fhid_protocol_version: U2FHID_PROTOCOL_VERSION,
                        major_device_version_number: MAJOR_DEVICE_VERSION_NUMBER,
                        minor_device_version_number: MINOR_DEVICE_VERSION_NUMBER,
                        build_device_version_number: BUILD_DEVICE_VERSION_NUMBER,
                        capabilities: CapabilityFlags::CAPFLAG_WINK,
                    },
                    channel_id,
                )))
            }
            RequestMessage::Ping { data } => Ok(Some(Output::ResponseMessage(
                ResponseMessage::Ping { data: data },
                channel_id,
            ))),
            RequestMessage::Wink => Ok(Some(Output::Request(Request::Wink))),
            RequestMessage::Lock { lock_time } => {
                if lock_time == 0 {
                    // TODO self.release_lock();
                } else {
                    // TODO enforce range of 1-10
                }
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;
    use self::rand::OsRng;
    use self::rand::Rand;
    use self::rand::Rng;

    #[test]
    fn channels_broadcast_channel_is_valid() {
        let channels = Channels::new();
        assert!(channels.is_valid(BROADCAST_CHANNEL_ID));
    }

    #[test]
    fn channels_allocated_channel_is_valid() {
        let mut channels = Channels::new();
        let channel_id = channels.allocate().unwrap();
        assert!(channels.is_valid(channel_id));
    }

    #[test]
    fn init() {
        let mut state_machine = StateMachine::new();
        init_channel(&mut state_machine);
    }

    fn init_channel(state_machine: &mut StateMachine) -> ChannelId {
        let mut os_rng = OsRng::new().unwrap();
        let request_nonce: [u8; 8] = os_rng.gen();
        let data = request_nonce.to_vec();
        let data_len = data.len();

        let res = state_machine
            .accept_packet(Packet::Initialization {
                channel_id: BROADCAST_CHANNEL_ID,
                command: Command::Init,
                data: data,
                payload_len: data_len,
            })
            .unwrap();

        match res {
            Some(Output::ResponseMessage(ResponseMessage::Init { channel_id, nonce, .. }, response_channel_id)) => {
                assert_eq!(response_channel_id, BROADCAST_CHANNEL_ID);
                assert_eq!(request_nonce, nonce);
                assert!(state_machine.channels.is_valid(channel_id));
                channel_id
            },
            _ => panic!(),
        }
    }

    #[test]
    fn ping() {
        let mut os_rng = OsRng::new().unwrap();
        let mut state_machine = StateMachine::new();
        let request_data: [u8; 8] = os_rng.gen();
        let packet_data = request_data.to_vec();
        let packet_data_len = packet_data.len();

        let channel_id = init_channel(&mut state_machine);

        let res = state_machine
            .accept_packet(Packet::Initialization {
                channel_id: channel_id,
                command: Command::Ping,
                data: packet_data,
                payload_len: packet_data_len,
            })
            .unwrap();

        match res {
            Some(Output::ResponseMessage(ResponseMessage::Ping { data }, response_channel_id)) => {
                assert_eq!(response_channel_id, channel_id);
                assert_eq!(request_data, data[..]);
            }
            _ => panic!()
        };
    }
}
