CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lpthread -lresolv

attack: attack.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f attack

.PHONY: clean
