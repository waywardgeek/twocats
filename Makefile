CC=gcc
CFLAGS=-std=c99 -Wall -pedantic -g -march=native
#CFLAGS=-std=c99 -Wall -pedantic -O3 -march=native -funroll-loops
#CFLAGS=-std=c99 -Wall -pedantic -O3 -msse4.2 -funroll-loops

all: tigerkdf-ref
#all: tigerkdf-ref tigerkdf tigerkdf-test counter tigerkdf-guess tigerkdf-phs

tigerkdf-ref: main.c tigerkdf-ref.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) main.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-ref

tigerkdf: main.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) -pthread main.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf

tigerkdf-guess: tigerkdf-guess.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) -pthread tigerkdf-guess.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-guess

tigerkdf-test: tigerkdf-test.c tigerkdf.h tigerkdf-impl.h tigerkdf-ref.c tigerkdf-common.c
	$(CC) $(CFLAGS) tigerkdf-test.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-test

tigerkdf-phs: tigerkdf-phs.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) -pthread tigerkdf-phs.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-phs

counter: counter.c
	$(CC) $(CFLAGS) counter.c -o counter

clean:
	rm -f tigerkdf-ref tigerkdf tigerkdf-test tigerkdf-guess tigerkdf-phs counter
