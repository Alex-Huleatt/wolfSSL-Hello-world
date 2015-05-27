CC=gcc
CFLAGS=-Wall
LIBS=-lwolfssl

all: server client

server: server.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

client: client.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all

clean:
	rm -f *.o server