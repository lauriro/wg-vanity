CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -pthread
LDFLAGS = -pthread

wg-vanity: wg-vanity.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f wg-vanity

.PHONY: clean
