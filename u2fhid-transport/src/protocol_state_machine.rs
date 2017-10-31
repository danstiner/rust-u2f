use std::collections::VecDeque;
use std::io;
use std::mem;
use std::time::Duration;

use futures::{Async, Future, Poll};
use futures::future;
use tokio_core::reactor::Handle;
use tokio_core::reactor::Timeout;
use slog::Logger;

use definitions::*;
use u2f_core::{self, ResponseError, Service, U2F};

macro_rules! try_some {
    ($e:expr) => (match $e {
        Ok(Some(t)) => return Ok(Some(t)),
        Ok(None) => {},
        Err(e) => return Err(From::from(e)),
    })
}

struct ReceiveState {
    buffer: Vec<u8>,
    command: Command,
    next_sequence_number: u8,
    payload_len: usize,
    channel_id: ChannelId,
    packet_timeout: Timeout,
    transaction_timeout: Timeout,
}

struct DispatchState {
    channel_id: ChannelId,
    future: Box<Future<Item = ResponseMessage, Error = io::Error>>,
    timeout: Timeout,
}

enum State {
    Idle,
    Receive(ReceiveState),
    Dispatch(DispatchState),
    Unknown,
}

impl State {
    fn take(&mut self) -> State {
        mem::replace(self, State::Unknown)
    }
}

const MAX_CHANNEL_ID: ChannelId = ChannelId(5);
const MIN_CHANNEL_ID: ChannelId = ChannelId(1);

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
            self.next_allocation = self.next_allocation.checked_add(1).unwrap();
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

enum LockState {
    None,
    Locked {
        channel_id: ChannelId,
        timeout: Timeout,
    },
}

impl LockState {
    fn lock(
        &mut self,
        duration: Duration,
        channel_id: ChannelId,
        handle: &Handle,
    ) -> io::Result<()> {
        *self = LockState::Locked {
            channel_id: channel_id,
            timeout: Timeout::new(duration, handle)?,
        };
        Ok(())
    }

    fn release(&mut self) {
        *self = LockState::None;
    }

    fn tick(&mut self) -> Result<(), io::Error> {
        let timed_out = match self {
            &mut LockState::Locked {
                ref channel_id,
                ref mut timeout,
            } => {
                match timeout.poll()? {
                    Async::Ready(()) => true,
                    Async::NotReady => false,
                }
            }
            _ => false,
        };

        if timed_out {
            *self = LockState::None;
        }

        Ok(())
    }
}

struct StateTransition<O> {
    new_state: State,
    output: O,
}

pub struct StateMachine<'a> {
    channels: Channels,
    handle: Handle,
    lock: LockState,
    logger: Logger,
    service: U2F<'a>,
    state: State,
}

impl<'a> StateMachine<'a> {
    pub fn new(service: U2F<'a>, handle: Handle, logger: Logger) -> StateMachine<'a> {
        StateMachine {
            channels: Channels::new(),
            handle: handle,
            lock: LockState::None,
            logger: logger,
            service: service,
            state: State::Idle,
        }
    }

    pub fn step(&mut self) -> Result<Option<Response>, io::Error> {
        // Tick the lock for possible timeout
        self.lock.tick();

        let transition = match self.state.take() {
            State::Receive(receive) => {
                // TODO check timeouts
                // receive.packet_timeout
                StateTransition {
                    new_state: State::Receive(receive),
                    output: None,
                }
            }
            State::Dispatch(mut dispatch) => {
                // check if ready
                match dispatch.future.poll()? {
                    Async::Ready(result) => {
                        let channel_id = dispatch.channel_id;
                        StateTransition {
                            new_state: State::Dispatch(dispatch),
                            output: Some(Response {
                                channel_id: channel_id,
                                message: result,
                            }),
                        }
                    }
                    Async::NotReady => StateTransition {
                        new_state: State::Dispatch(dispatch),
                        output: None,
                    },
                }
            }
            state => StateTransition {
                new_state: state,
                output: None,
            },
        };
        self.state = transition.new_state;
        Ok(transition.output)
    }

    pub fn accept_packet(&mut self, packet: Packet) -> Result<Option<Response>, io::Error> {
        debug!(self.logger, "check_channel_id");
        try_some!(self.check_channel_id(&packet));

        debug!(self.logger, "check_lock");
        try_some!(self.check_lock(&packet));

        debug!(self.logger, "step_with_packet");
        try_some!(self.step_with_packet(packet));

        debug!(self.logger, "try_complete_receive");
        try_some!(self.try_complete_receive());

        debug!(self.logger, "try_complete_dispatch");
        try_some!(self.try_complete_dispatch());

        Ok(None)
    }

    fn check_channel_id(&self, packet: &Packet) -> Result<Option<Response>, io::Error> {
        let channel_id = packet.channel_id();
        if !self.channels.is_valid(channel_id) {
            debug!(self.logger, "Invalid channel"; "id" => channel_id);
            Ok(Some(
                Self::error_output(ErrorCode::InvalidChannel, channel_id),
            ))
        } else {
            Ok(None)
        }
    }

    fn check_lock(&self, packet: &Packet) -> Result<Option<Response>, io::Error> {
        let packet_channel_id = packet.channel_id();
        match &self.lock {
            &LockState::Locked { channel_id, .. } => {
                if packet_channel_id != channel_id {
                    Ok(Some(Self::error_output(
                        ErrorCode::ChannelBusy,
                        packet_channel_id,
                    )))
                } else {
                    Ok(None)
                }
            }
            &LockState::None => Ok(None),
        }
    }

    fn step_with_packet(&mut self, packet: Packet) -> Result<Option<Response>, io::Error> {
        let transition = match (self.state.take(), packet) {
            (State::Idle,
             Packet::Initialization {
                 channel_id,
                 data,
                 payload_len,
                 command,
             }) => {
                debug!(self.logger, "Begin transaction"; "channel_id" => &channel_id, "command" => &command, "payload_len" => payload_len);
                StateTransition {
                    new_state: State::Receive(ReceiveState {
                        buffer: data.to_vec(),
                        channel_id: channel_id,
                        command: command,
                        next_sequence_number: 0,
                        payload_len: payload_len,
                        packet_timeout: Timeout::new(packet_timeout_duration(), &self.handle)?,
                        transaction_timeout: Timeout::new(
                            transaction_timeout_duration(),
                            &self.handle,
                        )?,
                    }),
                    output: None,
                }
            }
            (state @ State::Idle, Packet::Continuation { .. }) => {
                debug!(self.logger, "Out of order continuation packet, ignoring");
                StateTransition {
                    new_state: state,
                    output: None,
                }
            }
            (State::Receive(receive), Packet::Initialization { channel_id, .. }) => {
                if channel_id == receive.channel_id {
                    StateTransition {
                        new_state: State::Idle,
                        output: Some(Response {
                            channel_id: channel_id,
                            message: ResponseMessage::Error {
                                code: ErrorCode::InvalidMessageSequencing,
                            },
                        }),
                    }
                } else {
                    StateTransition {
                        new_state: State::Receive(receive),
                        output: Some(Response {
                            channel_id: channel_id,
                            message: ResponseMessage::Error { code: ErrorCode::ChannelBusy },
                        }),
                    }
                }
            }
            (State::Receive(mut receive),
             Packet::Continuation {
                 channel_id,
                 sequence_number,
                 data,
             }) => {
                if channel_id != receive.channel_id {
                    StateTransition {
                        new_state: State::Receive(receive),
                        output: Some(Response {
                            channel_id: channel_id,
                            message: ResponseMessage::Error { code: ErrorCode::ChannelBusy },
                        }),
                    }
                } else if sequence_number != receive.next_sequence_number {
                    StateTransition {
                        new_state: State::Idle,
                        output: Some(Response {
                            channel_id: channel_id,
                            message: ResponseMessage::Error {
                                code: ErrorCode::InvalidMessageSequencing,
                            },
                        }),
                    }
                } else {
                    receive.next_sequence_number += 1;
                    receive.buffer.extend_from_slice(&data);
                    receive.packet_timeout = Timeout::new(packet_timeout_duration(), &self.handle)?;
                    StateTransition {
                        new_state: State::Receive(receive),
                        output: None,
                    }
                }
            }
            (state @ State::Dispatch(_), packet) => StateTransition {
                new_state: state,
                output: Some(Self::error_output(
                    ErrorCode::ChannelBusy,
                    packet.channel_id(),
                )),
            },
            (State::Unknown, _) => panic!(),
        };

        self.state = transition.new_state;
        Ok(transition.output)
    }

    fn try_complete_receive(&mut self) -> Result<Option<Response>, io::Error> {
        let transition = match self.state.take() {
            State::Receive(receive) => {
                if receive.buffer.len() >= receive.payload_len {
                    debug!(self.logger, "Received entire payload"; "payload_len" => receive.payload_len);
                    let message = RequestMessage::decode(
                        &receive.command,
                        &receive.buffer[0..receive.payload_len],
                    ).unwrap();
                    let response_future = self.handle_request(Request {
                        channel_id: receive.channel_id,
                        message: message,
                    })?;
                    let dispatch_state = DispatchState {
                        channel_id: receive.channel_id,
                        future: response_future,
                        timeout: receive.transaction_timeout,
                    };
                    StateTransition {
                        new_state: State::Dispatch(dispatch_state),
                        output: None,
                    }
                } else {
                    StateTransition {
                        new_state: State::Receive(receive),
                        output: None,
                    }
                }
            }
            state => StateTransition {
                new_state: state,
                output: None,
            },
        };

        self.state = transition.new_state;
        Ok(transition.output)
    }

    fn try_complete_dispatch(&mut self) -> Result<Option<Response>, io::Error> {
        let transition = match self.state.take() {
            State::Dispatch(mut dispatch) => {
                match dispatch.future.poll()? {
                    Async::Ready(response) => {
                        StateTransition {
                            new_state: State::Idle,
                            output: Some(Response {
                                channel_id: dispatch.channel_id,
                                message: response.into(),
                            }),
                        }
                    }
                    Async::NotReady => {
                        StateTransition {
                            new_state: State::Dispatch(dispatch),
                            output: None,
                        }
                    }
                }
            }
            state => StateTransition {
                new_state: state,
                output: None,
            },
        };

        self.state = transition.new_state;
        Ok(transition.output)
    }

    fn error_output(error_code: ErrorCode, channel_id: ChannelId) -> Response {
        Response {
            channel_id: channel_id,
            message: ResponseMessage::Error { code: error_code },
        }
    }

    fn handle_request(
        &mut self,
        request: Request,
    ) -> Result<Box<Future<Item = ResponseMessage, Error = io::Error>>, io::Error> {
        let channel_id = request.channel_id;
        match request.message {
            RequestMessage::EncapsulatedRequest { data } => {
                // TODO no unwrap
                debug!(self.logger, "RequestMessage::EncapsulatedRequest"; "data.len" => data.len());
                let request = u2f_core::Request::decode(&data).unwrap();
                Ok(self.dispatch(request))
            }
            RequestMessage::Init { nonce } => {
                // TODO Check what channnel message came in on
                // TODO check unwrap
                let new_channel_id = self.channels.allocate().expect("Failed to allocate new channel");
                debug!(self.logger, "RequestMessage::Init"; "new_channel_id" => new_channel_id);
                Ok(Box::new(future::ok(ResponseMessage::Init {
                    nonce,
                    new_channel_id: new_channel_id,
                    u2fhid_protocol_version: U2FHID_PROTOCOL_VERSION,
                    major_device_version_number: MAJOR_DEVICE_VERSION_NUMBER,
                    minor_device_version_number: MINOR_DEVICE_VERSION_NUMBER,
                    build_device_version_number: BUILD_DEVICE_VERSION_NUMBER,
                    capabilities: CapabilityFlags::CAPFLAG_WINK,
                })))
            }
            RequestMessage::Ping { data } => {
                debug!(self.logger, "RequestMessage::Ping"; "data.len" => data.len());
                Ok(Box::new(future::ok(ResponseMessage::Pong { data: data })))
            }
            RequestMessage::Wink => Ok(self.dispatch(u2f_core::Request::Wink)),
            RequestMessage::Lock { lock_time } => {
                debug!(self.logger, "RequestMessage::Lock"; "lock_time" => lock_time.as_secs());
                if lock_time == Duration::from_secs(0) {
                    // TODO Enforce correct channel
                    self.lock.release();
                } else {
                    // TODO enforce range of 1-10
                    // TODO check channel_id matches current lock state
                    self.lock.lock(lock_time, channel_id, &self.handle)?;
                }
                Ok(Box::new(future::ok(ResponseMessage::Lock)))
            }
        }
    }

    fn dispatch(
        &mut self,
        request: u2f_core::Request,
    ) -> Box<Future<Item = ResponseMessage, Error = io::Error>> {
        Box::new(
            self.service
                .call(request)
                .map(|response| response.into())
                // .map_err(|err| match err {
                //     ResponseError::Io(io_err) => io_err,
                //     ResponseError::Signing(err) => {
                //         io::Error::new(io::ErrorKind::Other, "Signing error")
                //     }
                // }),
        )
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
            Some(Output::ResponseMessage(ResponseMessage::Init { channel_id, nonce, .. },
                                         response_channel_id)) => {
                assert_eq!(response_channel_id, BROADCAST_CHANNEL_ID);
                assert_eq!(request_nonce, nonce);
                assert!(state_machine.channels.is_valid(channel_id));
                channel_id
            }
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
            _ => panic!(),
        };
    }
}
