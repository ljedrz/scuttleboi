use crate::{Message, ScuttleBoi};

use bytes::Bytes;
use futures::{
    io::{AsyncRead, AsyncWrite},
    pin_mut,
};
use pea2pea::{
    connections::{Connection, ConnectionSide},
    protocols::{Handshaking, Reading, ReturnableConnection, Writing},
    Pea2Pea,
};
use ssb_boxstream::{BoxReader, BoxWriter};
use ssb_crypto::{
    secretbox::{Key, Nonce},
    NetworkKey, PublicKey,
};
use ssb_handshake::*;
use tokio::{
    io::{AsyncRead as TAR, AsyncWrite as TAW, ReadBuf},
    sync::mpsc,
    time::sleep,
};
use tokio_util::compat::{
    FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt, TokioAsyncReadCompatExt,
    TokioAsyncWriteCompatExt,
};
use tracing::*;

use std::{
    convert::TryInto,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

const AUTH_TAG_SIZE: usize = 16;
const BOX_HEADER_SIZE: usize = 34;

#[derive(Clone)]
pub(crate) struct Handshake {
    pub read_key: Key,
    pub read_starting_nonce: Nonce,
    pub write_key: Key,
    pub write_starting_nonce: Nonce,
    pub peer_key: PublicKey,
}

// a workaround impl to enable ssb_handshake functions that expect a full socket
struct ConnectionWrap(Connection);

impl AsyncRead for ConnectionWrap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let conn_reader = &mut self.0.reader.as_mut().unwrap();
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
        let conn_writer = &mut self.0.writer.as_mut().unwrap();
        pin_mut!(conn_writer);
        conn_writer.poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let conn_writer = &mut self.0.writer.as_mut().unwrap();
        pin_mut!(conn_writer);
        conn_writer.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let conn_writer = &mut self.0.writer.as_mut().unwrap();
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
                    let handshake = match !conn.0.side {
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

                    let (handshake, pk) = match handshake {
                        Ok(hs) => {
                            let handshake = Handshake {
                                read_key: hs.read_key,
                                read_starting_nonce: hs.read_starting_nonce,
                                write_key: hs.write_key,
                                write_starting_nonce: hs.write_starting_nonce,
                                peer_key: hs.peer_key,
                            };

                            (handshake, hs.peer_key)
                        }
                        Err(e) => {
                            error!(parent: sb.node().span(), "invalid handshake: {}", e);

                            if result_sender
                                .send(Err(io::ErrorKind::Other.into()))
                                .is_err()
                            {
                                unreachable!(); // can't recover if this happens
                            }
                            continue;
                        }
                    };

                    if let ConnectionSide::Responder = !conn.0.side {
                        sb.peers.lock().insert(conn.0.addr, pk);
                    }

                    sb.handshakes.lock().insert(pk, handshake);

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
    type Message = Message;

    fn enable_reading(&self) {
        let (conn_sender, mut conn_receiver) = mpsc::channel::<ReturnableConnection>(
            self.node().config().protocol_handler_queue_depth,
        );

        let self_clone = self.clone();
        let reading_task = tokio::spawn(async move {
            trace!(parent: self_clone.node().span(), "spawned the Reading handler task");

            loop {
                if let Some((mut conn, conn_returner)) = conn_receiver.recv().await {
                    let addr = conn.addr;
                    let reader = conn.reader.take().unwrap();
                    let pk = self_clone.peers.lock().get(&addr).unwrap().clone();
                    let handshake = self_clone.handshakes.lock().get(&pk).unwrap().clone();
                    let mut reader = BoxReader::new(
                        reader.compat(),
                        handshake.read_key,
                        handshake.read_starting_nonce,
                    )
                    .compat();
                    let mut buffer = vec![0; self_clone.node().config().conn_read_buffer_size]
                        .into_boxed_slice();

                    let (inbound_message_sender, mut inbound_message_receiver) =
                        mpsc::channel(self_clone.node().config().conn_inbound_queue_depth);

                    let processing_clone = self_clone.clone();
                    let inbound_processing_task = tokio::spawn(async move {
                        let node = processing_clone.node();
                        trace!(parent: node.span(), "spawned a task for processing messages from {}", addr);

                        loop {
                            if let Some(msg) = inbound_message_receiver.recv().await {
                                if let Err(e) = processing_clone.process_message(addr, msg).await {
                                    error!(parent: node.span(), "can't process an inbound message: {}", e);
                                    node.known_peers().register_failure(addr);
                                }
                            } else {
                                node.disconnect(addr);
                                break;
                            }
                        }
                    });

                    let reader_clone = self_clone.clone();
                    let reader_task = tokio::spawn(async move {
                        let node = reader_clone.node();
                        trace!(parent: node.span(), "spawned a task for reading messages from {}", addr);

                        let mut carry = 0;
                        loop {
                            match reader_clone
                                .read_from_stream(
                                    addr,
                                    &mut buffer,
                                    &mut reader,
                                    carry,
                                    &inbound_message_sender,
                                )
                                .await
                            {
                                Ok(leftover) => {
                                    carry = leftover;
                                }
                                Err(e) => {
                                    node.known_peers().register_failure(addr);
                                    match e.kind() {
                                        io::ErrorKind::InvalidData | io::ErrorKind::BrokenPipe => {
                                            node.disconnect(addr);
                                            break;
                                        }
                                        io::ErrorKind::Other => {
                                            sleep(Duration::from_secs(
                                                node.config().invalid_read_delay_secs,
                                            ))
                                            .await;
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                            }
                        }
                    });

                    conn.tasks.push(reader_task);
                    conn.tasks.push(inbound_processing_task);

                    if conn_returner.send(Ok(conn)).is_err() {
                        unreachable!("could't return a Connection to the Node");
                    }
                } else {
                    error!("the Reading protocol is down!");
                    break;
                }
            }
        });

        self.node()
            .set_reading_handler((conn_sender, reading_task).into());
    }

    fn read_message(
        &self,
        _source: SocketAddr,
        buffer: &[u8],
    ) -> io::Result<Option<(Self::Message, usize)>> {
        if buffer.len() >= BOX_HEADER_SIZE {
            let len = u16::from_be_bytes(buffer[..2].try_into().unwrap());

            if buffer[2..].len() >= AUTH_TAG_SIZE {
                if buffer[2 + AUTH_TAG_SIZE..].len() >= len as usize {
                    trace!("complete message read: {:?}", buffer);
                    unimplemented!();
                } else {
                    trace!("incomplete read: {:?}", buffer);
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn process_message(&self, source: SocketAddr, message: Self::Message) -> io::Result<()> {
        unimplemented!()
    }
}

impl Writing for ScuttleBoi {
    fn enable_writing(&self) {
        let (conn_sender, mut conn_receiver) = mpsc::channel::<ReturnableConnection>(
            self.node().config().protocol_handler_queue_depth,
        );

        let self_clone = self.clone();
        let writing_task = tokio::spawn(async move {
            trace!(parent: self_clone.node().span(), "spawned the Writing handler task");

            loop {
                if let Some((mut conn, conn_returner)) = conn_receiver.recv().await {
                    let addr = conn.addr;
                    let writer = conn.writer.take().unwrap();
                    let pk = self_clone.peers.lock().get(&addr).unwrap().clone();
                    let handshake = self_clone.handshakes.lock().get(&pk).unwrap().clone();
                    let mut writer = BoxWriter::new(
                        writer.compat_write(),
                        handshake.read_key,
                        handshake.read_starting_nonce,
                    )
                    .compat_write();
                    let mut buffer = vec![0; self_clone.node().config().conn_write_buffer_size]
                        .into_boxed_slice();

                    let (outbound_message_sender, mut outbound_message_receiver) =
                        mpsc::channel::<Bytes>(
                            self_clone.node().config().conn_outbound_queue_depth,
                        );

                    let writer_clone = self_clone.clone();
                    let writer_task = tokio::spawn(async move {
                        let node = writer_clone.node();
                        trace!(parent: node.span(), "spawned a task for writing messages to {}", addr);

                        loop {
                            if let Some(msg) = outbound_message_receiver.recv().await {
                                match writer_clone
                                    .write_to_stream(&msg, addr, &mut buffer, &mut writer)
                                    .await
                                {
                                    Ok(len) => {
                                        node.known_peers().register_sent_message(addr, len);
                                        node.stats().register_sent_message(len);
                                        trace!(parent: node.span(), "sent {}B to {}", len, addr);
                                    }
                                    Err(e) => {
                                        node.known_peers().register_failure(addr);
                                        error!(parent: node.span(), "couldn't send a message to {}: {}", addr, e);
                                    }
                                }
                            } else {
                                node.disconnect(addr);
                                break;
                            }
                        }
                    });

                    conn.tasks.push(writer_task);
                    conn.outbound_message_sender = Some(outbound_message_sender);

                    if conn_returner.send(Ok(conn)).is_err() {
                        unreachable!("could't return a Connection to the Node");
                    }
                } else {
                    error!("the Writing protocol is down!");
                    break;
                }
            }
        });

        // register the WritingHandler with the Node
        self.node()
            .set_writing_handler((conn_sender, writing_task).into());
    }

    fn write_message(&self, _: SocketAddr, payload: &[u8], buffer: &mut [u8]) -> io::Result<usize> {
        unimplemented!()
    }
}
