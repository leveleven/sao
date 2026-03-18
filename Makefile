# sao — build and install binaries (sao client, sao-server)
#
#   make install              # release build + install to PREFIX/bin (may need sudo)
#   make install PREFIX=~/.local
#   make DESTDIR=/tmp/stage install   # staging for packages

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=

.PHONY: all release build install uninstall test fmt clippy check clean

all: release

release build:
	cargo build --release -p sao-server -p sao-client

install: release
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 755 target/release/sao "$(DESTDIR)$(BINDIR)/sao"
	install -m 755 target/release/sao-server "$(DESTDIR)$(BINDIR)/sao-server"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/sao" "$(DESTDIR)$(BINDIR)/sao-server"

test:
	cargo test --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace -- -D warnings

check: fmt clippy test

clean:
	cargo clean
