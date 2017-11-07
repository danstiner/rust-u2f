use std::io::{self, BufRead};
use std::thread;

use futures::{Future, Sink, Stream};
use futures::sync::mpsc::channel;

pub fn stdin_stream() -> Box<Stream<Item = String, Error = io::Error>> {
    let (mut tx, rx) = channel(0);
    thread::spawn(move || {
        let input = io::stdin();
        for line in input.lock().lines() {
            match tx.send(line).wait() {
                Ok(s) => tx = s,
                Err(_) => break,
            }
        }
    });
    return Box::new(rx.then(|e| e.unwrap()));
}
