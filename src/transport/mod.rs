pub mod rest;
pub mod websocket;

use uuid::*;

pub fn uuid() -> String {
    let mut rng_bytes: [u8; 16] = [0; 16];

    unsafe {
        sodium_sys::randombytes_buf(rng_bytes.as_mut_ptr() as *mut libc::c_void, 16);
    }

    return Builder::from_random_bytes(rng_bytes)
        .into_uuid()
        .to_string();
}
