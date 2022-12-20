pub mod rest;
pub mod websocket;

use uuid::*;

pub fn uuid() -> String {
    let mut rng_bytes: [u8; 16] = [0; 16];
    dryoc::rng::copy_randombytes(&mut rng_bytes);

    return Builder::from_random_bytes(rng_bytes)
        .into_uuid()
        .to_string();
}
