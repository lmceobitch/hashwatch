CC = gcc
CFLAGS = -O2 -Wall -Wextra

all: hasher timeline

hasher: hasher.c ../include/sha256.h
	$(CC) $(CFLAGS) -o hasher hasher.c

timeline: timeline.c
	$(CC) $(CFLAGS) -o timeline timeline.c

clean:
	rm -f hasher timeline

.PHONY: all clean
