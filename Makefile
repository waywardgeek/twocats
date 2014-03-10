CC=gcc
CFLAGS=-std=c99 -Wall -pthread -pedantic -g -march=native
#CFLAGS=-std=c99 -Wall -pthread -pedantic -O3 -march=native -funroll-loops
#CFLAGS=-std=c99 -Wall -pthread -pedantic -O3 -msse4.2 -funroll-loops

SOURCE= \
./blake2/blake2s.c \
./hkdf/hkdf.c \
./hkdf/hmac.c \
./hkdf/sha1.c \
./hkdf/sha224-256.c \
./hkdf/sha384-512.c \
./hkdf/usha.c \
./tigerkdf-common.c

OBJS=$(patsubst %.c,obj/%.o,$(SOURCE))

#all: tigerkdf-ref tigerkdf tigerkdf-test tigerkdf-phs tigerkdf-enc tigerkdf-dec
all: tigerkdf-ref 

obj/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

tigerkdf-ref: $(OBJS) main.c tigerkdf-ref.c tigerkdf-impl.h tigerkdf.h
	$(CC) $(CFLAGS) -o tigerkdf-ref $(OBJS) main.c tigerkdf-ref.c

#tigerkdf: main.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	#$(CC) $(CFLAGS) -pthread main.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf

#tigerkdf-test: tigerkdf-test.c tigerkdf.h tigerkdf-impl.h tigerkdf-ref.c tigerkdf-common.c
	#$(CC) $(CFLAGS) tigerkdf-test.c tigerkdf-ref.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-test

#tigerkdf-phs: tigerkdf-phs.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	#$(CC) $(CFLAGS) -pthread tigerkdf-phs.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-phs

#tigerkdf-enc: tigerkdf-enc.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	#$(CC) $(CFLAGS) -pthread tigerkdf-enc.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-enc -lssl -lcrypto

#tigerkdf-dec: tigerkdf-dec.c tigerkdf.c tigerkdf-common.c tigerkdf.h tigerkdf-impl.h pbkdf2.c pbkdf2.h
	#$(CC) $(CFLAGS) -pthread tigerkdf-dec.c tigerkdf.c tigerkdf-common.c pbkdf2.c blake2/blake2s.c -o tigerkdf-dec -lssl -lcrypto

depend:
	makedepend -- $(CFLAGS) -- $(SOURCE)
	mkdir -p obj/blake2
	mkdir -p obj/hkdf

clean:
	rm -rf obj tigerkdf-ref tigerkdf tigerkdf-test tigerkdf-phs tigerkdf-enc tigerkdf-dec
	mkdir -p obj/blake2
	mkdir -p obj/hkdf

# DO NOT DELETE

./blake2/blake2s.o: /usr/include/stdint.h /usr/include/bits/wordsize.h
./blake2/blake2s.o: /usr/include/string.h /usr/include/_ansi.h
./blake2/blake2s.o: /usr/include/newlib.h /usr/include/sys/config.h
./blake2/blake2s.o: /usr/include/machine/ieeefp.h /usr/include/sys/features.h
./blake2/blake2s.o: /usr/include/sys/reent.h /usr/include/sys/_types.h
./blake2/blake2s.o: /usr/include/machine/_types.h
./blake2/blake2s.o: /usr/include/machine/_default_types.h
./blake2/blake2s.o: /usr/include/sys/lock.h /usr/include/sys/cdefs.h
./blake2/blake2s.o: /usr/include/sys/string.h /usr/include/stdio.h
./blake2/blake2s.o: /usr/include/sys/types.h /usr/include/machine/types.h
./blake2/blake2s.o: /usr/include/sys/stdio.h ./blake2/blake2.h
./blake2/blake2s.o: ./blake2/blake2-impl.h ./blake2/blake2-config.h
./blake2/blake2s.o: ./blake2/blake2s-round.h ./blake2/blake2s-load-sse2.h
./hkdf/hkdf.o: ./hkdf/sha.h /usr/include/stdint.h
./hkdf/hkdf.o: /usr/include/bits/wordsize.h /usr/include/string.h
./hkdf/hkdf.o: /usr/include/_ansi.h /usr/include/newlib.h
./hkdf/hkdf.o: /usr/include/sys/config.h /usr/include/machine/ieeefp.h
./hkdf/hkdf.o: /usr/include/sys/features.h /usr/include/sys/reent.h
./hkdf/hkdf.o: /usr/include/sys/_types.h /usr/include/machine/_types.h
./hkdf/hkdf.o: /usr/include/machine/_default_types.h /usr/include/sys/lock.h
./hkdf/hkdf.o: /usr/include/sys/cdefs.h /usr/include/sys/string.h
./hkdf/hkdf.o: /usr/include/stdlib.h /usr/include/machine/stdlib.h
./hkdf/hkdf.o: /usr/include/alloca.h
./hkdf/hmac.o: ./hkdf/sha.h /usr/include/stdint.h
./hkdf/hmac.o: /usr/include/bits/wordsize.h
./hkdf/sha1.o: ./hkdf/sha.h /usr/include/stdint.h
./hkdf/sha1.o: /usr/include/bits/wordsize.h ./hkdf/sha-private.h
./hkdf/sha224-256.o: ./hkdf/sha.h /usr/include/stdint.h
./hkdf/sha224-256.o: /usr/include/bits/wordsize.h ./hkdf/sha-private.h
./hkdf/sha384-512.o: ./hkdf/sha.h /usr/include/stdint.h
./hkdf/sha384-512.o: /usr/include/bits/wordsize.h ./hkdf/sha-private.h
./hkdf/usha.o: ./hkdf/sha.h /usr/include/stdint.h
./hkdf/usha.o: /usr/include/bits/wordsize.h
./main.o: /usr/include/stdio.h /usr/include/_ansi.h /usr/include/newlib.h
./main.o: /usr/include/sys/config.h /usr/include/machine/ieeefp.h
./main.o: /usr/include/sys/features.h /usr/include/sys/reent.h
./main.o: /usr/include/sys/_types.h /usr/include/machine/_types.h
./main.o: /usr/include/machine/_default_types.h /usr/include/sys/lock.h
./main.o: /usr/include/sys/types.h /usr/include/machine/types.h
./main.o: /usr/include/sys/stdio.h /usr/include/sys/cdefs.h
./main.o: /usr/include/stdint.h /usr/include/bits/wordsize.h
./main.o: /usr/include/stdlib.h /usr/include/machine/stdlib.h
./main.o: /usr/include/alloca.h /usr/include/ctype.h /usr/include/string.h
./main.o: /usr/include/sys/string.h /usr/include/getopt.h tigerkdf.h
./main.o: tigerkdf-impl.h blake2/blake2.h
./tigerkdf-common.o: /usr/include/stdio.h /usr/include/_ansi.h
./tigerkdf-common.o: /usr/include/newlib.h /usr/include/sys/config.h
./tigerkdf-common.o: /usr/include/machine/ieeefp.h
./tigerkdf-common.o: /usr/include/sys/features.h /usr/include/sys/reent.h
./tigerkdf-common.o: /usr/include/sys/_types.h /usr/include/machine/_types.h
./tigerkdf-common.o: /usr/include/machine/_default_types.h
./tigerkdf-common.o: /usr/include/sys/lock.h /usr/include/sys/types.h
./tigerkdf-common.o: /usr/include/machine/types.h /usr/include/sys/stdio.h
./tigerkdf-common.o: /usr/include/sys/cdefs.h /usr/include/stdint.h
./tigerkdf-common.o: /usr/include/bits/wordsize.h /usr/include/stdlib.h
./tigerkdf-common.o: /usr/include/machine/stdlib.h /usr/include/alloca.h
./tigerkdf-common.o: /usr/include/string.h /usr/include/sys/string.h
./tigerkdf-common.o: /usr/include/time.h /usr/include/machine/time.h
./tigerkdf-common.o: tigerkdf.h tigerkdf-impl.h blake2/blake2.h
./tigerkdf-ref.o: /usr/include/stdio.h /usr/include/_ansi.h
./tigerkdf-ref.o: /usr/include/newlib.h /usr/include/sys/config.h
./tigerkdf-ref.o: /usr/include/machine/ieeefp.h /usr/include/sys/features.h
./tigerkdf-ref.o: /usr/include/sys/reent.h /usr/include/sys/_types.h
./tigerkdf-ref.o: /usr/include/machine/_types.h
./tigerkdf-ref.o: /usr/include/machine/_default_types.h
./tigerkdf-ref.o: /usr/include/sys/lock.h /usr/include/sys/types.h
./tigerkdf-ref.o: /usr/include/machine/types.h /usr/include/sys/stdio.h
./tigerkdf-ref.o: /usr/include/sys/cdefs.h /usr/include/stdint.h
./tigerkdf-ref.o: /usr/include/bits/wordsize.h /usr/include/stdlib.h
./tigerkdf-ref.o: /usr/include/machine/stdlib.h /usr/include/alloca.h
./tigerkdf-ref.o: /usr/include/string.h /usr/include/sys/string.h tigerkdf.h
./tigerkdf-ref.o: tigerkdf-impl.h blake2/blake2.h
./tigerkdf.o: /usr/include/stdio.h /usr/include/_ansi.h /usr/include/newlib.h
./tigerkdf.o: /usr/include/sys/config.h /usr/include/machine/ieeefp.h
./tigerkdf.o: /usr/include/sys/features.h /usr/include/sys/reent.h
./tigerkdf.o: /usr/include/sys/_types.h /usr/include/machine/_types.h
./tigerkdf.o: /usr/include/machine/_default_types.h /usr/include/sys/lock.h
./tigerkdf.o: /usr/include/sys/types.h /usr/include/machine/types.h
./tigerkdf.o: /usr/include/sys/stdio.h /usr/include/sys/cdefs.h
./tigerkdf.o: /usr/include/stdint.h /usr/include/bits/wordsize.h
./tigerkdf.o: /usr/include/stdlib.h /usr/include/machine/stdlib.h
./tigerkdf.o: /usr/include/alloca.h /usr/include/string.h
./tigerkdf.o: /usr/include/sys/string.h /usr/include/pthread.h
./tigerkdf.o: /usr/include/signal.h /usr/include/sys/signal.h
./tigerkdf.o: /usr/include/sched.h /usr/include/sys/sched.h
./tigerkdf.o: /usr/include/time.h /usr/include/machine/time.h
./tigerkdf.o: /usr/include/byteswap.h tigerkdf.h tigerkdf-impl.h
./tigerkdf.o: blake2/blake2.h blake2/blake2-config.h
