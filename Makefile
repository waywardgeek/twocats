CC=gcc
CFLAGS=-std=c99 -Wall -pedantic -g -march=native
#CFLAGS=-std=c99 -Wall -pedantic -O3 -march=native -funroll-loops

all: tigerkdf-ref tigerkdf tigerkdf-test

tigerkdf-ref: main.c tigerkdf-ref.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) main.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-ref

tigerkdf: main.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) -pthread main.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf

tigerkdf-test: tigerkdf-test.c tigerkdf.h tigerkdf-impl.h tigerkdf-ref.c tigerkdf-common.c
	$(CC) $(CFLAGS) tigerkdf-test.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-test

clean:
	rm -f tigerkdf-ref tigerkdf tigerkdf-test
