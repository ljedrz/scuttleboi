use scuttleboi::ScuttleBoi;

use pea2pea::protocols::{Handshaking, Reading, Writing};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

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
    sb.enable_reading();
    sb.enable_writing();

    std::future::pending::<()>().await;
}
