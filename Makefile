.PHONY: all build release debug clean run test check profile bench

# Compiler flags
RUSTFLAGS_RELEASE := -C target-cpu=native -C codegen-units=1 -C opt-level=3
CARGO_FLAGS := --jobs $(shell nproc)

# Default target
all: release

# Production optimized build
release:
	RUSTFLAGS="$(RUSTFLAGS_RELEASE)" cargo build --release $(CARGO_FLAGS)
	strip target/release/vanity-pgp-miner

# Debug build
debug:
	cargo build $(CARGO_FLAGS)

# Clean build artifacts
clean:
	cargo clean
	rm -rf gpg_export/

# Run the miner
run:
	@if [ -z "$(name)" ] || [ -z "$(email)" ]; then \
		echo "Usage: make run name=\"Your Name\" email=\"your@email.com\" [total=2000000]"; \
		exit 1; \
	fi
	./target/release/vanity-pgp-miner "$(name)" "$(email)" "$(total)"

# Build and run optimized version
mine: release
	@if [ -z "$(name)" ] || [ -z "$(email)" ]; then \
		echo "Usage: make mine name=\"Your Name\" email=\"your@email.com\" [total=2000000]"; \
		exit 1; \
	fi
	./target/release/vanity-pgp-miner "$(name)" "$(email)" "$(total)"

# Show help
help:
	@echo "Vanity PGP Key Miner Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make mine name=\"Your Name\" email=\"your@email.com\""
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build release version (default)"
	@echo "  release - Build with optimizations"
	@echo "  debug   - Build debug version"
	@echo "  clean   - Remove build artifacts"
	@echo "  run     - Run existing build"
	@echo "  mine    - Build and run"