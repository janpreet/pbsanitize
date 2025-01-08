CC=gcc
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    CFLAGS=-Wall -Wextra -O2 -framework ApplicationServices
else
    CFLAGS=-Wall -Wextra -O2
endif

all: pbsanitize test

pbsanitize: pbsanitize.c
	$(CC) $(CFLAGS) -o pbsanitize pbsanitize.c

test: test.c
	$(CC) $(CFLAGS) -o test test.c

clean:
	rm -f pbsanitize test

install: pbsanitize
	cp pbsanitize /usr/local/bin/