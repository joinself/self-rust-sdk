# self-rust-sdk
A Rust SDK for interact with the self network


# development
To update the flatbuffer definitions:
```sh
cd protocol
flatc --rust --filename-suffix "" messaging.fbs
cd siggraph
flatc --rust --filename-suffix "" siggraph.fbs
```

# testing