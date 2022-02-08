CC=gcc
FLAGS=-Wall -Wextra -Wshadow -g
LIBS=-lcrypto -lssl -lpthread

all: sfmap clientmod

clientmod: clientmod.c
	$(CC) $^ -o $@ $(FLAGS) $(LIBS)

sfmap: sfmap.c
	$(CC) $^ -o $@ $(FLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -rf sfmap clientmod
