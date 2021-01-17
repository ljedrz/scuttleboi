use parking_lot::Mutex;
use pea2pea::{Node, NodeConfig, Pea2Pea};
use ssb_crypto::PublicKey;
use ssb_keyfile::Keypair;
use tokio::{net::UdpSocket, task::JoinHandle, time::sleep};
use tracing::*;

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    str,
    sync::Arc,
    time::Duration,
};

#[derive(Clone)]
pub struct ScuttleBoi {
    node: Node,
    pub local_addr: IpAddr,
    pub keypair: Keypair,
    pub peers: Arc<Mutex<HashMap<SocketAddr, PublicKey>>>,
    pub tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
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

        let client = Self {
            node,
            local_addr,
            keypair,
            peers: Default::default(),
            tasks: Default::default(),
        };

        client.start_udp_tasks().await;

        Ok(client)
    }

    pub async fn connect_to_peer(&self, addr: SocketAddr, pk: PublicKey) -> io::Result<()> {
        self.peers.lock().insert(addr, pk);

        self.node().connect(addr).await
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

    async fn start_udp_tasks(&self) {
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
