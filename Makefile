# Makefile for TigerPHS code examples

BINS += tigerphs-ref
DEPS = Makefile

CC=gcc
CFLAGS=-std=c99 -Wall -pthread -pedantic -g -march=native
#CFLAGS=-std=c99 -Wall -pthread -pedantic -O3 -march=native -funroll-loops
#CFLAGS=-std=c99 -Wall -pthread -pedantic -O3 -msse4.2 -funroll-loops

SOURCE= \
blake2/blake2s.c \
hkdf/hkdf.c \
hkdf/hmac.c \
hkdf/sha1.c \
hkdf/sha224-256.c \
hkdf/sha384-512.c \
hkdf/usha.c \
tigerphs-common.c

OBJS=$(patsubst %.c,obj/%.o,$(SOURCE))

#all: tigerphs-ref tigerphs tigerphs-test tigerphs-phs tigerphs-enc tigerphs-dec
all: ${BINS}

-include $(OBJS:.o=.d)

tigerphs-ref: $(DEPS) $(OBJS) main.c tigerphs-ref.c tigerphs-impl.h tigerphs.h
	$(CC) $(CFLAGS) -o tigerphs-ref $(OBJS) main.c tigerphs-ref.c

#tigerphs: main.c tigerphs.c tigerphs-common.c tigerphs.h tigerphs-impl.h pbkdf2.c pbkdf2.h
	#$(CC) $(CFLAGS) -pthread main.c tigerphs.c tigerphs-common.c pbkdf2.c blake2/blake2s.c -o tigerphs

#tigerphs-test: tigerphs-test.c tigerphs.h tigerphs-impl.h tigerphs-ref.c tigerphs-common.c
	#$(CC) $(CFLAGS) tigerphs-test.c tigerphs-ref.c tigerphs-common.c pbkdf2.c blake2/blake2s.c -o tigerphs-test

#tigerphs-phs: tigerphs-phs.c tigerphs.c tigerphs-common.c tigerphs.h tigerphs-impl.h pbkdf2.c pbkdf2.h
	#$(CC) $(CFLAGS) -pthread tigerphs-phs.c tigerphs.c tigerphs-common.c pbkdf2.c blake2/blake2s.c -o tigerphs-phs

#tigerphs-enc: tigerphs-enc.c tigerphs.c tigerphs-common.c tigerphs.h tigerphs-impl.h pbkdf2.c pbkdf2.h
	#$(CC) $(CFLAGS) -pthread tigerphs-enc.c tigerphs.c tigerphs-common.c pbkdf2.c blake2/blake2s.c -o tigerphs-enc -lssl -lcrypto

#tigerphs-dec: tigerphs-dec.c tigerphs.c tigerphs-common.c tigerphs.h tigerphs-impl.h pbkdf2.c pbkdf2.h
	#$(CC) $(CFLAGS) -pthread tigerphs-dec.c tigerphs.c tigerphs-common.c pbkdf2.c blake2/blake2s.c -o tigerphs-dec -lssl -lcrypto

clean:
	rm -rf obj tigerphs-ref tigerphs tigerphs-test tigerphs-phs tigerphs-enc tigerphs-dec
	mkdir -p obj/blake2
	mkdir -p obj/hkdf

depend: clean
	@echo "* Making dependencies for $(OBJS)"
	@$(MAKE) -s $(OBJS)
	@echo "* Making dependencies - done"

obj/%.o: %.c
	@echo "* Compiling $@";
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) -MM $(CFLAGS) $< > $*.d
	@cp -f $*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

