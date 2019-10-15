CC=gcc
CFLAGS=-Wall -I.
dpt: dpt.c
	$(CC) $(CFLAGS) -o dpt dpt.c
clean:
	rm -f dpt
