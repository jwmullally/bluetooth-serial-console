PREFIX := /usr/local
SYSCONFDIR := /etc

all: ;

install:
	install -m 0755 -D bluetooth-serial-console.py $(DESTDIR)$(PREFIX)/bin/bluetooth-serial-console
	install -m 0755 -D -t $(DESTDIR)$(SYSCONFDIR)/systemd/system/ bluetooth-serial-console.service

test:
	./bluetooth-serial-console.py --discoverable --auth-cmd ./sample-auth-cmd.sh