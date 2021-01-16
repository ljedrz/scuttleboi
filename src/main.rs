use parking_lot::Mutex;
use pea2pea::{
    connections::ConnectionSide,
    protocols::{Handshaking, Reading, ReturnableConnection, Writing},
    Node, NodeConfig, Pea2Pea,
};
use ssb_crypto::PublicKey;
use ssb_keyfile::Keypair;
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle, time::sleep};
use tracing::*;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

use std::{
    io,
    net::{IpAddr, SocketAddr},
    str,
    sync::Arc,
    time::Duration,
};

#[derive(Clone)]
struct ScuttleBoi {
    node: Node,
    local_addr: IpAddr,
    keypair: Keypair,
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
            )
            .into_bytes();

            loop {
                socket
                    .writable()
                    .await
                    .expect("can't check if the UDP socket is writable!");
                socket
                    .send_to(&packet, broadcast_addr)
                    .await
                    .expect("couldn't advertise my presence via UDP!");

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
                    Ok((n, addr)) => {
                        if let Some((addr, pk)) = sb.read_udp_packet(&buf[..n]) {
                            if addr.ip() != sb.local_addr {
                                info!(parent: sb.node().span(), "found a local peer! addr: {}, pk: {}", addr, pk.as_base64());
                            }
                        } else {
                            trace!(parent: sb.node().span(), "invalid UDP packet from {}", addr);
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

impl Handshaking for ScuttleBoi {
    fn enable_handshaking(&self) {
        let (from_node_sender, mut from_node_receiver) = mpsc::channel::<ReturnableConnection>(
            self.node().config().protocol_handler_queue_depth,
        );

        // spawn a background task dedicated to handling the handshakes
        let self_clone = self.clone();
        let handshaking_task = tokio::spawn(async move {
            loop {
                if let Some((mut conn, result_sender)) = from_node_receiver.recv().await {
                    let peer_name = match !conn.side {
                        ConnectionSide::Initiator => {
                            debug!(parent: conn.node.span(), "handshaking with {} as the initiator", conn.addr);
                        }
                        ConnectionSide::Responder => {
                            debug!(parent: conn.node.span(), "handshaking with {} as the responder", conn.addr);
                        }
                    };

                    // return the Connection to the node
                    if result_sender.send(Ok(conn)).is_err() {
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

    //sb.enable_reading();
    //sb.enable_writing();

    sb.start_udp_tasks().await;

    std::future::pending::<()>().await;
}
