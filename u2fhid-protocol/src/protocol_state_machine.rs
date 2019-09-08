use std::io;
use std::mem;
use std::time::Duration;

use futures::{Async, Future};
use futures::future;
use slog::Logger;
use tokio_core::reactor::Handle;
use tokio_core::reactor::Timeout;

use definitions::*;
use u2f_core::{self, Service};

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

const MAX_CHANNEL_ID: ChannelId = ChannelId(BROADCAST_CHANNEL_ID.0 - 1);
const MIN_CHANNEL_ID: ChannelId = ChannelId(1);

#[derive(Debug)]
struct Channels {
    next_allocation: ChannelId,
}

impl Channels {
    fn new() -> Channels {
        Channels {
            next_allocation: MIN_CHANNEL_ID,
        }
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
        let is_in_allocated_range =
            channel_id >= MIN_CHANNEL_ID && channel_id < self.next_allocation;
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
        // Check lock timeout
        let timed_out = match *self {
            LockState::Locked {
                ref mut timeout, ..
            } => match timeout.poll()? {
                Async::Ready(()) => true,
                Async::NotReady => false,
            },
            _ => false,
        };

        if timed_out {
            *self = LockState::None;
        }

        // TODO Check frame and transation timeouts

        Ok(())
    }
}

struct StateTransition<O> {
    new_state: State,
    output: O,
}

pub struct StateMachine<S> {
    channels: Channels,
    handle: Handle,
    lock: LockState,
    logger: Logger,
    service: S,
    state: State,
}

impl<S> StateMachine<S>
where
    S: Service<
        Request = u2f_core::Request,
        Response = u2f_core::Response,
        Error = io::Error,
        Future = Box<Future<Item = u2f_core::Response, Error = io::Error>>,
    >,
    ResponseMessage: From<<S as u2f_core::Service>::Response>,
{
    pub fn new(service: S, handle: Handle, logger: Logger) -> StateMachine<S> {
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
        self.lock.tick()?;

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
                            new_state: State::Idle,
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
            Ok(Some(Self::error_output(
                ErrorCode::InvalidChannel,
                channel_id,
            )))
        } else {
            Ok(None)
        }
    }

    fn check_lock(&self, packet: &Packet) -> Result<Option<Response>, io::Error> {
        let packet_channel_id = packet.channel_id();
        match self.lock {
            LockState::Locked { channel_id, .. } => {
                if packet_channel_id != channel_id {
                    Ok(Some(Self::error_output(
                        ErrorCode::ChannelBusy,
                        packet_channel_id,
                    )))
                } else {
                    Ok(None)
                }
            }
            LockState::None => Ok(None),
        }
    }

    fn step_with_packet(&mut self, packet: Packet) -> Result<Option<Response>, io::Error> {
        let transition = match (self.state.take(), packet) {
            (
                State::Idle,
                Packet::Initialization {
                    channel_id,
                    data,
                    payload_len,
                    command,
                },
            ) => {
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
                    debug!(self.logger, "Invalid message sequencing");
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
                    debug!(self.logger, "Other channel busy with transaction");
                    StateTransition {
                        new_state: State::Receive(receive),
                        output: Some(Response {
                            channel_id: channel_id,
                            message: ResponseMessage::Error {
                                code: ErrorCode::ChannelBusy,
                            },
                        }),
                    }
                }
            }
            (
                State::Receive(mut receive),
                Packet::Continuation {
                    channel_id,
                    sequence_number,
                    data,
                },
            ) => {
                if channel_id != receive.channel_id {
                    StateTransition {
                        new_state: State::Receive(receive),
                        output: Some(Response {
                            channel_id: channel_id,
                            message: ResponseMessage::Error {
                                code: ErrorCode::ChannelBusy,
                            },
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
                    let bytes = &receive.buffer[0..receive.payload_len];
                    debug!(self.logger, "Received payload"; "len" => receive.payload_len);
                    match RequestMessage::decode(&receive.command, bytes) {
                        Err(RequestMessageDecodeError::UnsupportedCommand(Command::Unknown { .. })) => {
                            info!(self.logger, "Unknown command. Responding with InvalidCommand error to encourage fallback to U2F protocol");
                            StateTransition {
                                new_state: State::Idle,
                                output: Some(Response {
                                    channel_id: receive.channel_id,
                                    message: ResponseMessage::Error {
                                        code: ErrorCode::InvalidCommand,
                                    },
                                }),
                            }
                        },
                        Err(error) => {
                            debug!(self.logger, "Unable to decode request message"; "error" => error);
                            StateTransition {
                                new_state: State::Idle,
                                output: Some(Response {
                                    channel_id: receive.channel_id,
                                    message: ResponseMessage::Error {
                                        code: ErrorCode::Other,
                                    },
                                }),
                            }
                        },
                        Ok(message) => {
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
                        }
                    }
                } else {
                    debug!(self.logger, "Payload incomplete"; "payload_len" => receive.payload_len, "receive_len" => receive.buffer.len());
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
            State::Dispatch(mut dispatch) => match dispatch.future.poll()? {
                Async::Ready(response) => StateTransition {
                    new_state: State::Idle,
                    output: Some(Response {
                        channel_id: dispatch.channel_id,
                        message: response,
                    }),
                },
                Async::NotReady => StateTransition {
                    new_state: State::Dispatch(dispatch),
                    output: None,
                },
            },
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
                let new_channel_id = self.channels
                    .allocate()
                    .expect("Failed to allocate new channel");
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
        Box::new(self.service.call(request).map(|response| response.into()))
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;
    use self::rand::{OsRng, Rng};
    use slog::{self, Drain};
    use slog_stdlog;
    use tokio_core::reactor::Core;

    struct FakeU2FService;

    impl Service for FakeU2FService {
        type Request = u2f_core::Request;
        type Response = u2f_core::Response;
        type Error = io::Error;
        type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

        fn call(&self, _req: Self::Request) -> Self::Future {
            panic!("Fake service, not implemented");
        }
    }

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
        let logger = slog::Logger::root(slog_stdlog::StdLog.fuse(), o!());
        let core = Core::new().unwrap();
        let mut state_machine = StateMachine::new(FakeU2FService, core.handle(), logger);
        init_channel(&mut state_machine);
    }

    fn init_channel<S>(state_machine: &mut StateMachine<S>) -> ChannelId
    where
        S: Service<
            Request = u2f_core::Request,
            Response = u2f_core::Response,
            Error = io::Error,
            Future = Box<Future<Item = u2f_core::Response, Error = io::Error>>,
        >,
    {
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
            Some(Response {
                channel_id: response_channel_id,
                message:
                    ResponseMessage::Init {
                        new_channel_id,
                        nonce,
                        ..
                    },
            }) => {
                assert_eq!(response_channel_id, BROADCAST_CHANNEL_ID);
                assert_eq!(request_nonce, nonce);
                assert!(state_machine.channels.is_valid(new_channel_id));
                new_channel_id
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ping() {
        let logger = slog::Logger::root(slog_stdlog::StdLog.fuse(), o!());
        let core = Core::new().unwrap();
        let mut os_rng = OsRng::new().unwrap();
        let mut state_machine = StateMachine::new(FakeU2FService, core.handle(), logger);
        let ping_data: [u8; 8] = os_rng.gen();
        let packet_data = ping_data.to_vec();
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
            Some(Response {
                channel_id: response_channel_id,
                message:
                    ResponseMessage::Pong {
                        data: response_data,
                    },
            }) => {
                assert_eq!(response_channel_id, channel_id);
                assert_eq!(response_data[..], ping_data);
            }
            _ => panic!(),
        };
    }
}
