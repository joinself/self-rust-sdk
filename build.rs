fn main() {
    prost_build::compile_protos(&["src/protocol/p2p/p2p.proto"], &["src/"])
        .expect("failed to build protobuf bindings");
    tonic_build::compile_protos("src/protocol/rpc/rpc.proto")
        .expect("failed to build protobuf bindings");
}
