CC=gcc
#CFLAGS=-std=c99 -Wall -pedantic -g -march=native
CFLAGS=-std=c99 -Wall -pedantic -O3 -march=native -funroll-loops
#CFLAGS=-std=c99 -Wall -pedantic -O3 -msse4.2 -funroll-loops

all: tigerkdf-ref tigerkdf tigerkdf-test tigerkdf-phs tigerkdf-enc tigerkdf-dec

tigerkdf-ref: main.c tigerkdf-ref.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) main.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-ref

tigerkdf: main.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) -pthread main.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf

tigerkdf-test: tigerkdf-test.c tigerkdf.h tigerkdf-impl.h tigerkdf-ref.c tigerkdf-common.c
	$(CC) $(CFLAGS) tigerkdf-test.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-test

tigerkdf-phs: tigerkdf-phs.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) -pthread tigerkdf-phs.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-phs

tigerkdf-enc: tigerkdf-enc.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) -pthread tigerkdf-enc.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-enc -lssl -lcrypto

tigerkdf-dec: tigerkdf-dec.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) -pthread tigerkdf-dec.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-dec -lssl -lcrypto

clean:
	rm -f tigerkdf-ref tigerkdf tigerkdf-test tigerkdf-phs tigerkdf-enc tigerkdf-dec
