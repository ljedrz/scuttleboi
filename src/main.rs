use parking_lot::Mutex;
use pea2pea::{connections::ConnectionSide, Node, NodeConfig, Pea2Pea, protocols::{Handshaking, Reading, Writing, ReturnableConnection}};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle, time::sleep};
use tracing::*;

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

#[derive(Clone)]
struct ScuttleBoi {
    node: Node,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Pea2Pea for ScuttleBoi {
    fn node(&self) -> &Node {
        &self.node
    }
}

impl ScuttleBoi {
    pub async fn new() -> io::Result<Self> {
        let config = NodeConfig {
            name: Some("scuttleboi".into()),
            desired_listening_port: Some(3030),
            allow_random_port: false,
            conn_read_buffer_size: 5000,
            ..Default::default()
        };

        let ret = Self {
            node: Node::new(Some(config)).await?,
            tasks: Default::default(),
        };

        Ok(ret)
    }

    pub fn start_pub_task(&self) {
        let node = self.node().clone();
        let task = tokio::spawn(async move {
            debug!(parent: node.span(), "starting the UDP advertising task");

            let udp_socket = UdpSocket::bind("0.0.0.0:8008").await.expect("couldn't open the UDP advertisement socket!");
            udp_socket.set_broadcast(true).unwrap();

            let mut buf = [0u8; 64];
            let broadcast_addr: SocketAddr = "255.255.255.255:8008".parse().unwrap();

            loop {
                match udp_socket.try_recv(&mut buf) {
                    Ok(n) => info!("{:?}", &buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {},
                    Err(e) => error!("couldn't read a UDP broadcast: {}", e),
                }

                udp_socket.writable().await.expect("can't check if the UDP socket is writable!");
                udp_socket.send_to(b"TODO", broadcast_addr).await.expect("couldn't advertise my presence via UDP!");

                sleep(Duration::from_secs(1)).await;
            }
        });

        self.tasks.lock().push(task);
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
    tracing_subscriber::fmt::init();

    let sb = ScuttleBoi::new().await.unwrap();

    //sb.enable_reading();
    //sb.enable_writing();

    sb.start_pub_task();

    std::future::pending::<()>().await;
}
