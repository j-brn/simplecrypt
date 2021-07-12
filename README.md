# simplecrypt

Wrapper around [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide) that supports encrypting and
decrypting arbitrary data with a secret key.

## Installation

`simplecrypt` is hosted on [crates.io](https://crates.io/crates/simplecrypt) To use the crate, 
just add it to the `[dependencies]` section in your `Cargo.toml` file.

```toml
simplecrypt = "1.0"
```

## Docs

You can find the documentation on the [docs.rs page](https://docs.rs/simplecrypt/1.0.2/simplecrypt/).

To build the documentation locally, clone the repository and run 

```shell script
cargo doc --open
```

## Tests

To run the tests, clone the repository and run

```shell script
cargo test
```
