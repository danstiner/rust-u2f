struct LineProto;

impl<T: AsyncRead + AsyncWrite + 'static> ServerProto<T> for LineProto
{
    type Request = String;
    type Response = String;

    // `Framed<T, LineCodec>` is the return value of
    // `io.framed(LineCodec)`
    type Transport = Framed<T, LineCodec>;
    type BindTransport = Result<Self::Transport, io::Error>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        Ok(io.framed(LineCodec))
    }
}

impl<T: AsyncRead + AsyncWrite + 'static> ServerProto<T> for LineProto
{
    type Request = String;
    type Response = String;

    // `Framed<T, LineCodec>` is the return value of
    // `io.framed(LineCodec)`
    type Transport = Framed<T, LineCodec>;
    type BindTransport = Box<Future<Item = Self::Transport,
                                   Error = io::Error>>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        // Construct the line-based transport
        let transport = io.framed(LineCodec);

        // The handshake requires that the client sends `You ready?`,
        // so wait to receive that line. If anything else is sent,
        // error out the connection
        Box::new(transport.into_future()
            // If the transport errors out, we don't care about
            // the transport anymore, so just keep the error
            .map_err(|(e, _)| e)
            .and_then(|(line, transport)| {
                // A line has been received, check to see if it
                // is the handshake
                match line {
                    Some(ref msg) if msg == "You ready?" => {
                        println!("SERVER: received client handshake");
                        // Send back the acknowledgement
                        let ret = transport.send("Bring it!".into());
                        Box::new(ret) as Self::BindTransport
                    }
                    _ => {
                        // The client sent an unexpected handshake,
                        // error out the connection
                        println!("SERVER: client handshake INVALID");
                        let err = io::Error::new(io::ErrorKind::Other,
                                                 "invalid handshake");
                        let ret = future::err(err);
                        Box::new(ret) as Self::BindTransport
                    }
                }
            }))
    }
}
