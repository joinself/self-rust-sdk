#[allow(clippy::module_inception)]
pub mod p2p {
    include!(concat!(env!("OUT_DIR"), "/p2p.rs"));
}

pub use p2p::*;
