# Vanity PGP Key Miner

A high-performance vanity PGP key miner written in Rust using Sequoia-PGP. This tool generates PGP keys until it finds one with a fingerprint matching specified patterns.

## Linux Dependencies

For Ubuntu 24.04+:

```sh
sudo apt-get install build-essential pkg-config clang nettle-dev libgmp-dev libpcsclite-dev libclang-dev
```

Build the optimized version:

```sh
make release
```

## Usage

Basic usage:

```sh
# Default: generate 2 million keys
make mine name="Your Name" email="your@email.com"

# Custom total: generate 1 million keys
make mine name="Your Name" email="your@email.com" total=1000000
```

The program will create a `gpg_export` directory containing:

* `public_key_N.asc`: Public keys for matches found
* `found_keys.txt`: Log of all matches with patterns

## Pattern Examples

The miner searches for keys matching these patterns:

* `DEADBEEF`: Classic hexspeak
* `CAFEBABE`: Java magic number
* `DEADC0DE`: Dead code
* `FEEDFACE`: Feed face

## Performance Tips

Build with native optimizations (already included in Makefile):

```sh
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## License

MIT License - see LICENSE file for details
