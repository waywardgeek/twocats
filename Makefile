CFLAGS=-O3 -std=c11 -W -Wall -funroll-loops
#CFLAGS=-O3 -std=c11 -W -Wall -msse4.2
#CFLAGS=-g -std=c11 -W -Wall

all: tigerkdf-ref tigerkdf tigerkdf-test

tigerkdf-ref: main.c tigerkdf-ref.c tigerkdf-common.c tigerkdf.h pbkdf2.c pbkdf2.h
	gcc $(CFLAGS) main.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-ref

tigerkdf: main.c tigerkdf-sse.c tigerkdf-common.c tigerkdf.h pbkdf2.c pbkdf2.h
	gcc $(CFLAGS) -msse4.2 -pthread main.c tigerkdf-sse.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf
	#gcc -mavx -g -O3 -S -std=c99 -m64 main.c tigerkdf-sse.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c

tigerkdf-test: tigerkdf-test.c tigerkdf.h tigerkdf-ref.c tigerkdf-common.c
	gcc $(CFLAGS) tigerkdf-test.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-test

clean:
	rm -f tigerkdf-ref tigerkdf tigerkdf-test
