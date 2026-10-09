# Freelay server

Relay, but free.

Fork of [Relay server](https://github.com/No-Instructions/relay-server),
itself derived from [y-sweet](https://github.com/jamsocket/y-sweet).
Includes a self-hosted Ed25519-authenticated control plane; no proprietary
account, subscription, or persistent token-signing key is needed.

Work in progress: not yet a production release. Use a dedicated test store.

```sh
cd crates
cargo build --release -p freelay-server
```

On Nix systems, build or run the repository flake directly:

```sh
nix build
nix run -- version
```

The flake also exports `nixosModules.default`. Import it into a NixOS system,
set `services.freelay.enable = true` and `services.freelay.configFile` to a TOML
configuration path, and put persistent database/object paths below
`/var/lib/freelay`. The module deliberately leaves TLS and reverse-proxy policy
to the consuming host configuration.

Copy [freelay.example.toml](freelay.example.toml), create
its data directory, add Owner public keys, and run:

```sh
crates/target/release/freelay serve --config freelay.toml
```

See [operation and recovery](docs/OPERATIONS.md) and
[protocol and security boundaries](docs/PROTOCOL.md).
The [Freelay Obsidian plugin](https://github.com/thesilverage/freelay)
is the intended client. Existing SDKs describe the upstream data plane, not
the new control API.

Run `cargo test --workspace` from `crates/`.
The control plane is required. Generic upstream creation/authentication and
physical-delete routes are not exposed.

See [LICENSE](LICENSE) for retained upstream attribution and the MIT license.
