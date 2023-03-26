# self-rust-sdk
A Rust SDK for interact with the self network


# development
To update the flatbuffer definitions:
```sh
cd protocol/messaging
flatc --rust --filename-suffix "" messaging.fbs
cd protocol/siggraph
flatc --rust --filename-suffix "" siggraph.fbs
```

# testing