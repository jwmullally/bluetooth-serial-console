PREFIX := /usr/local
SYSCONFDIR := /etc

all: ;

install:
	install -m 0755 -D bluetooth-serial-console.py $(DESTDIR)$(PREFIX)/bin/bluetooth-serial-console
	install -m 0755 -D bluetooth-automatic-pairing.py $(DESTDIR)$(PREFIX)/bin/bluetooth-automatic-pairing
	install -m 0755 -D -t $(DESTDIR)$(SYSCONFDIR)/systemd/system/ bluetooth-serial-console.service
	install -m 0755 -D -t $(DESTDIR)$(SYSCONFDIR)/systemd/system/ bluetooth-automatic-pairing.service

test: test-pairing test-serial

test-pairing:
	./bluetooth-automatic-pairing.py --auth-cmd ./sample-auth-cmd.sh

test-serial:
	./bluetooth-serial-console.py