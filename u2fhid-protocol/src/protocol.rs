
/// Transport adapting the U2FHID protocol on top of an underlying framed HID USB transport.
/// 
/// U2F messages may be too long to fit in a single HID report event, so there
/// is inherit complexity required to frame such messages as a series of HID
/// report events using the extended length APDU encoding.
/// 
/// See https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html#protocol-structure-and-data-framing
pub struct U2fHid<T: Sink<Packet> + Stream, S> {
    state_machine: StateMachine<S>,
    transport: T,
}

impl<T, E> U2fHidProtocol<T>
where
    T: Sink<SinkItem = Packet, SinkError = E> + Stream<Item = Packet, Error = E>,
    E: From<io::Error>,
{
    pub fn new(
        transport: T,
    ) -> Self {
        Self {
            state_machine: StateMachine::new(),
            transport,
        }
    }
}





// impl<T, S, E> Future for U2fHidProtocol<T, S>
// where
//     T: Sink<SinkItem = Packet, SinkError = E> + Stream<Item = Packet, Error = E>,
//     S: Service<
//         Request = u2f_core::Request,
//         Response = u2f_core::Response,
//         Error = io::Error,
//         Future = Box<dyn Future<Item = u2f_core::Response, Error = io::Error>>,
//     >,
//     E: From<io::Error>,
// {
//     type Output = Result<(), E>;

//     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         loop {
//             trace!("Poll U2fHid");

//             // Always tick the transport first
//             // TODO self.transport.tick();

//             try_ready!(self.transport.poll_complete());

//             if let Some(response) = self.state_machine.step()? {
//                 trace!("Send response"; "channel_id" => &response.channel_id, "message" => &response.message);
//                 self.transport.start_send(response)?;
//                 continue;
//             }

//             match try_ready!(self.transport.poll()) {
//                 Some(packet) => {
//                     trace!("Got packet from transport"; "packet" => &packet);
//                     if let Some(response) = self.state_machine.accept_packet(packet)? {
//                         trace!("Send response"; "channel_id" => &response.channel_id, "message" => &response.message);
//                         self.transport.start_send(response)?;
//                     }
//                 }
//                 None => {
//                     // TODO close
//                     return Ok(Async::Ready(()));
//                 }
//             };
//         }
//     }
// }
