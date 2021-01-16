use futures::{
    io::{AsyncRead, AsyncWrite},
    pin_mut,
};
use parking_lot::Mutex;
use pea2pea::{
    connections::{Connection, ConnectionSide},
    protocols::{Handshaking, Reading, ReturnableConnection, Writing},
    Node, NodeConfig, Pea2Pea,
};
use ssb_crypto::{NetworkKey, PublicKey};
use ssb_handshake::*;
use ssb_keyfile::Keypair;
use tokio::{
    io::{AsyncRead as TAR, AsyncWrite as TAW, ReadBuf},
    net::UdpSocket,
    sync::mpsc,
    task::JoinHandle,
    time::sleep,
};
use tracing::*;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

#[derive(Clone)]
struct ScuttleBoi {
    node: Node,
    local_addr: IpAddr,
    keypair: Keypair,
    peers: Arc<Mutex<HashMap<SocketAddr, PublicKey>>>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Pea2Pea for ScuttleBoi {
    fn node(&self) -> &Node {
        &self.node
    }
}

impl ScuttleBoi {
    pub async fn new() -> io::Result<Self> {
        let node_config = NodeConfig {
            name: Some("scuttleboi".into()),
            desired_listening_port: Some(8008),
            allow_random_port: false,
            conn_read_buffer_size: 5000,
            ..Default::default()
        };
        let node = Node::new(Some(node_config)).await?;

        // find the local IP address
        let local_addr = {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect("8.8.8.8:80").await?;
            socket.local_addr()?.ip()
        };
        debug!(parent: node.span(), "local addr: {}", local_addr);

        let keypair = ssb_keyfile::generate(&mut Vec::new())?;
        debug!(parent: node.span(), "temporary public key: {}", keypair.public.as_base64());

        let ret = Self {
            node,
            local_addr,
            keypair,
            peers: Default::default(),
            tasks: Default::default(),
        };

        Ok(ret)
    }

    fn read_udp_packet(&self, packet: &[u8]) -> Option<(SocketAddr, PublicKey)> {
        if packet.starts_with(&b"net:"[..]) {
            let packet = &packet[4..];
            let idx = packet.iter().position(|&b| b == b'~')?;
            let addr = str::from_utf8(&packet[..idx])
                .ok()?
                .parse::<SocketAddr>()
                .ok()?;

            if packet[idx + 1..].starts_with(&b"shs:"[..]) {
                let pk = PublicKey::from_base64(str::from_utf8(&packet[idx + 5..]).ok()?)?;

                Some((addr, pk))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub async fn start_udp_tasks(&self) {
        let udp_socket = Arc::new(
            UdpSocket::bind("0.0.0.0:8008")
                .await
                .expect("couldn't open the UDP advertisement socket!"),
        );

        trace!(parent: self.node().span(), "starting the UDP advertising task");
        let sb = self.clone();
        let socket = udp_socket.clone();
        let advertising_task = tokio::spawn(async move {
            socket.set_broadcast(true).unwrap();
            let broadcast_addr: SocketAddr = "255.255.255.255:8008".parse().unwrap();
            let packet = format!(
                "net:{}:8008~shs:{}",
                sb.local_addr,
                sb.keypair.public.as_base64()
            );

            loop {
                socket
                    .writable()
                    .await
                    .expect("can't check if the UDP socket is writable!");
                socket
                    .send_to(packet.as_bytes(), broadcast_addr)
                    .await
                    .expect("couldn't advertise my presence via UDP!");

                // trace!(parent: sb.node().span(), "advertised using the following packet: {}", packet);

                sleep(Duration::from_secs(1)).await;
            }
        });
        self.tasks.lock().push(advertising_task);

        trace!(parent: self.node().span(), "starting the UDP advertisement reader task");
        let sb = self.clone();
        let advertisement_reader_task = tokio::spawn(async move {
            let mut buf = [0u8; 128];

            loop {
                udp_socket
                    .readable()
                    .await
                    .expect("can't check if the UDP socket is readable!");
                match udp_socket.try_recv_from(&mut buf) {
                    Ok((n, sender)) => {
                        if let Some((addr, pk)) = sb.read_udp_packet(&buf[..n]) {
                            if addr.ip() != sb.local_addr {
                                info!(parent: sb.node().span(), "found a local peer! addr: {}, pk: {}", addr, pk.as_base64());
                                sb.peers.lock().insert(addr, pk);
                            }
                        } else {
                            trace!(parent: sb.node().span(), "invalid UDP packet from {}", sender);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => error!("couldn't read a UDP broadcast: {}", e),
                }
            }
        });
        self.tasks.lock().push(advertisement_reader_task);
    }
}

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

#[tokio::main]
async fn main() {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter.add_directive("mio=off".parse().unwrap()),
        _ => EnvFilter::default()
            .add_directive(LevelFilter::INFO.into())
            .add_directive("mio=off".parse().unwrap()),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let sb = ScuttleBoi::new().await.unwrap();

    sb.enable_handshaking();
    //sb.enable_reading();
    //sb.enable_writing();

    sb.start_udp_tasks().await;

    std::future::pending::<()>().await;
}
