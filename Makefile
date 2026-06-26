BIN := dist/bwsshd
PREFIX := $(HOME)/.local
UNITDIR := $(HOME)/.config/systemd/user

.PHONY: build test clean install uninstall

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN) .

test:
	go test ./...

clean:
	rm -f $(BIN)

install: build
	install -Dm755 $(BIN) $(PREFIX)/bin/bwsshd
	install -Dm644 systemd/bwsshd.service $(UNITDIR)/bwsshd.service
	systemctl --user daemon-reload
	systemctl --user enable --now bwsshd.service
	@echo "logs: journalctl --user -u bwsshd -f"

uninstall:
	-systemctl --user disable --now bwsshd.service
	rm -f $(PREFIX)/bin/bwsshd $(UNITDIR)/bwsshd.service
	systemctl --user daemon-reload
