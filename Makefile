CC=gcc
#CFLAGS=-std=c99 -Wall -pedantic -g -march=native
CFLAGS=-std=c99 -Wall -pedantic -g -O3 -march=native
#CFLAGS=-O3 -std=c99 -W -Wall -funroll-loops
#CFLAGS=-O3 -std=c99 -W -Wall -msse4.2
#CFLAGS=-g -std=c99 -W -Wall

all: tigerkdf-ref tigerkdf tigerkdf-test

tigerkdf-ref: main.c tigerkdf-ref.c tigerkdf-common.c tigerkdf.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) main.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-ref

tigerkdf: main.c tigerkdf-sse.c tigerkdf-common.c tigerkdf.h pbkdf2.c pbkdf2.h
	$(CC) $(CFLAGS) -pthread main.c tigerkdf-sse.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf
	#$(CC) -mavx -g -O3 -S -std=c99 -m64 main.c tigerkdf-sse.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c

tigerkdf-test: tigerkdf-test.c tigerkdf.h tigerkdf-ref.c tigerkdf-common.c
	$(CC) $(CFLAGS) tigerkdf-test.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-test

clean:
	rm -f tigerkdf-ref tigerkdf tigerkdf-test
