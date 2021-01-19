use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Pub {
    author: Option<String>,
    content: Content,
}

#[derive(Serialize, Deserialize, Debug)]
struct Content {
    r#type: String,
    address: Address,
}

#[derive(Serialize, Deserialize, Debug)]
struct Address {
    host: String,
    port: u16,
    key: String,
}

// TODO
pub struct Message;
