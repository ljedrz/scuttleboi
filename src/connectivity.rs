use crate::client::ScuttleBoi;

use futures::{
    io::{AsyncRead, AsyncWrite},
    pin_mut,
};
use pea2pea::{
    connections::{Connection, ConnectionSide},
    protocols::{Handshaking, Reading, ReturnableConnection, Writing},
    Pea2Pea,
};
use ssb_crypto::NetworkKey;
use ssb_handshake::*;
use tokio::{
    io::{AsyncRead as TAR, AsyncWrite as TAW, ReadBuf},
    sync::mpsc,
};
use tracing::*;

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

// a workaround impl to enable ssb_handshake functions that expect a full socket
struct ConnectionWrap(Connection);

impl AsyncRead for ConnectionWrap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let conn_reader = &mut self.0.reader.as_mut().unwrap().reader;
        pin_mut!(conn_reader);
        conn_reader
            .poll_read(cx, &mut ReadBuf::new(buf))
            .map(|_| Ok(buf.len()))
    }
}

impl AsyncWrite for ConnectionWrap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let conn_writer = &mut self.0.writer.as_mut().unwrap().writer;
        pin_mut!(conn_writer);
        conn_writer.poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let conn_writer = &mut self.0.writer.as_mut().unwrap().writer;
        pin_mut!(conn_writer);
        conn_writer.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let conn_writer = &mut self.0.writer.as_mut().unwrap().writer;
        pin_mut!(conn_writer);
        conn_writer.poll_shutdown(cx)
    }
}

impl Handshaking for ScuttleBoi {
    fn enable_handshaking(&self) {
        let (from_node_sender, mut from_node_receiver) = mpsc::channel::<ReturnableConnection>(
            self.node().config().protocol_handler_queue_depth,
        );

        // spawn a background task dedicated to handling the handshakes
        let sb = self.clone();
        let handshaking_task = tokio::spawn(async move {
            let nk = NetworkKey::SSB_MAIN_NET;

            loop {
                if let Some((conn, result_sender)) = from_node_receiver.recv().await {
                    let mut conn = ConnectionWrap(conn);
                    let handshake_keys = match !conn.0.side {
                        ConnectionSide::Initiator => {
                            debug!(parent: conn.0.node.span(), "handshaking with {} as the initiator", conn.0.addr);

                            let peer_pk = if let Some(pk) = sb.peers.lock().get(&conn.0.addr) {
                                *pk
                            } else {
                                error!(
                                    "can't connect to {}; its public key is not known",
                                    conn.0.addr
                                );
                                if result_sender
                                    .send(Err(io::ErrorKind::Other.into()))
                                    .is_err()
                                {
                                    unreachable!(); // can't recover if this happens
                                }
                                continue;
                            };

                            client_side(&mut conn, &nk, &sb.keypair, &peer_pk).await
                        }
                        ConnectionSide::Responder => {
                            debug!(parent: conn.0.node.span(), "handshaking with {} as the responder", conn.0.addr);

                            server_side(&mut conn, &nk, &sb.keypair).await
                        }
                    };

                    debug!(parent: sb.node().span(), "succesfully handshaken with {}", conn.0.addr);

                    // return the Connection to the node
                    if result_sender.send(Ok(conn.0)).is_err() {
                        unreachable!(); // can't recover if this happens
                    }
                }
            }
        });

        self.node()
            .set_handshake_handler((from_node_sender, handshaking_task).into());
    }
}

#[async_trait::async_trait]
impl Reading for ScuttleBoi {
    type Message = String;

    fn read_message(
        &self,
        _source: SocketAddr,
        buffer: &[u8],
    ) -> io::Result<Option<(Self::Message, usize)>> {
        unimplemented!()
    }

    async fn process_message(&self, source: SocketAddr, message: Self::Message) -> io::Result<()> {
        unimplemented!()
    }
}

impl Writing for ScuttleBoi {
    fn write_message(&self, _: SocketAddr, payload: &[u8], buffer: &mut [u8]) -> io::Result<usize> {
        unimplemented!()
    }
}