# Shipped inside the release archive. Installs the prebuilt bwsshd binary and
# its systemd --user unit; no build step (the binary is already in the archive).
PREFIX ?= $(HOME)/.local
UNITDIR ?= $(HOME)/.config/systemd/user

.PHONY: install uninstall
install:
	install -Dm755 bwsshd $(PREFIX)/bin/bwsshd
	install -Dm644 bwsshd.service $(UNITDIR)/bwsshd.service
	systemctl --user daemon-reload
	systemctl --user enable --now bwsshd.service
	@echo "logs: journalctl --user -u bwsshd -f"

uninstall:
	-systemctl --user disable --now bwsshd.service
	rm -f $(PREFIX)/bin/bwsshd $(UNITDIR)/bwsshd.service
	systemctl --user daemon-reload
