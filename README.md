# kasen

The handshake engine for Open Gensokyo Network, administratively supported by Starspun Works.

Source: [opengensokyonet/kasen](https://github.com/opengensokyonet/kasen).

This repository currently contains one package, `kasen_handshake`: TLS 1.3 handshake messages, extensions, key schedule and handshake engines. The current APIs are experimental and are not stable production APIs.

## Layout

- [`crates/kasen_handshake`](crates/kasen_handshake/README.md): the TLS 1.3 handshake for QUIC; depends on the `nitori_call`, `nitori_io`, `nitori_crypto` and `nitori_sync` packages of [nitori](https://github.com/opengensokyonet/nitori).

## Development

Install [rustup](https://rustup.rs/). The repository pins `nightly-2026-11-03` with rustfmt, Clippy and the `x86_64-unknown-none` target in `rust-toolchain.toml`. Run commands from the repository root so rustup selects this toolchain. Nightly language features are required. Packages remain unpublished (`publish = false`). `kasen_handshake` builds without the standard library, with `alloc`; the parts that need it are behind its default `std` feature. It is checked on `x86_64-unknown-none`, a target without the standard library that has 64-bit atomics. `nitori_crypto_aws_lc`, a development dependency, also needs a C compiler and CMake.

SNAFU is pinned to commit `03cb8d2e52a3b0b33a39cc3d4ce8a7075fa4ab58` in the public [Open Gensokyo Network fork](https://github.com/opengensokyonet/snafu), pending [upstream PR #565](https://github.com/shepmaster/snafu/pull/565). Cargo fetches this source automatically; no sibling checkout is needed. The nitori packages are Git dependencies pinned to a commit.

From the repository root:

```sh
cargo fetch --locked
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy --locked -p kasen_handshake --target x86_64-unknown-none --no-default-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc
cargo test --locked --workspace --doc --all-features
```

For local development, an ignored `.cargo/config.toml` may patch `snafu`, `snafu-derive` and the nitori packages to local checkouts under `[patch."https://github.com/opengensokyonet/snafu"]` and `[patch."https://github.com/opengensokyonet/nitori"]`. Keep that configuration and the resulting path-source lockfile changes out of commits; the committed lockfile records the public Git sources.

## License

Software and code examples are licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Explanatory documentation is licensed under [CC BY 4.0](LICENSE-CC-BY). Contributors retain copyright in their contributions. Project names and logos are not licensed as trademarks by these licenses.
