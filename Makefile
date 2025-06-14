EXE = freedoas
CC = cc
CFLAGS = -Wall -Wextra -pedantic -std=c99
PREFIX = /usr/local
MANPREFIX ?= $(PREFIX)/share

# build with line numbers on die()
dev:
	$(CC) -g -DDEV=1 $(CFLAGS) -o $(EXE) freedoas.c
	chmod +s $(EXE)

# build without line numbers on die()
release:
	$(CC) $(CFLAGS) -o $(EXE) freedoas.c
	chmod +s $(EXE)
	strip $(EXE)

install: release
	install -D -m 4755 $(EXE) $(PREFIX)/bin/$(EXE)
	@mkdir -p $(MANPREFIX)/man1
	@mkdir -p $(MANPREFIX)/man5
	install -D -m 644 freedoas.1 $(MANPREFIX)/man1/$(EXE).1
	install -D -m 644 doas.conf.5 $(MANPREFIX)/man5/doas.conf.5

clean:
	rm -f $(EXE)
