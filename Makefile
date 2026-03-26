# sao — build and install binaries (sao client, sao-server)
#
#   make install              # release build + install to PREFIX/bin (run as root or: sudo make install)
#   make install PREFIX=~/.local
#   make install-service      # build, init /etc/sao, install + systemd, start (run as root or: sudo make install-service)
#   make install-service NO_START=1
#   make DESTDIR=/tmp/stage install   # staging for packages

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
CONFIG_PATH ?= /etc/sao/config.yaml
UNIT_DIR ?= /etc/systemd/system

.PHONY: all release build install install-service uninstall test fmt clippy check clean

all: release

release build:
	cargo build --release -p sao-server -p sao-client

install: release
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 755 target/release/sao "$(DESTDIR)$(BINDIR)/sao"
	install -m 755 target/release/sao-server "$(DESTDIR)$(BINDIR)/sao-server"

install-service: release
	@set -e; \
	echo "sao install: PREFIX=$(PREFIX) BINDIR=$(BINDIR)"; \
	if [ ! -f "$(CONFIG_PATH)" ]; then \
		echo "Initializing $(CONFIG_PATH) and TLS materials..."; \
		mkdir -p /etc/sao; \
		"$(CURDIR)/target/release/sao-server" init --config "$(CONFIG_PATH)"; \
		echo "Add sao-ed25519 lines to /etc/sao/authorized_keys."; \
	else \
		echo "Config exists at $(CONFIG_PATH), skipping init."; \
	fi; \
	echo "Installing binaries to $(BINDIR)..."; \
	install -d "$(BINDIR)"; \
	install -m 755 target/release/sao "$(BINDIR)/sao"; \
	install -m 755 target/release/sao-server "$(BINDIR)/sao-server"; \
	VER=$$(systemctl --version 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1 || echo 0); \
	if [ -z "$$VER" ] || [ "$$VER" -lt 226 ] 2>/dev/null; then \
		echo "ERROR: systemd $$VER < 226 — cannot fully restrict sao permissions. Upgrade systemd or use AppArmor/SELinux."; \
		exit 1; \
	fi; \
	if [ "$$VER" -ge 230 ] 2>/dev/null; then \
		UNIT_SRC="$(CURDIR)/deploy/systemd/sao-server.service"; \
	else \
		echo "systemd $$VER (226–229): using legacy unit (ProtectSystem=strict)"; \
		UNIT_SRC="$(CURDIR)/deploy/systemd/sao-server.service.legacy"; \
	fi; \
	if [ "$(BINDIR)" != "/usr/local/bin" ]; then \
		sed "s|/usr/local/bin|$(BINDIR)|g" "$$UNIT_SRC" | tee "$(UNIT_DIR)/sao-server.service" > /dev/null; \
	else \
		cp "$$UNIT_SRC" "$(UNIT_DIR)/sao-server.service"; \
	fi; \
	echo "Installing systemd unit..."; \
	systemctl daemon-reload; \
	systemctl enable sao-server; \
	if [ -z "$(NO_START)" ]; then \
		echo "Starting sao-server..."; \
		systemctl start sao-server; \
		systemctl status sao-server --no-pager || true; \
	else \
		echo "Skipping start (NO_START=1). Add keys, then: systemctl start sao-server"; \
	fi; \
	echo "Install complete. Client: $(BINDIR)/sao"

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
