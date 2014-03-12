# Makefile for twocats

DEPS = Makefile

CC=gcc
#CFLAGS=-std=c99 -Wall -pthread -pedantic -g -march=native
CFLAGS=-std=c99 -Wall -pthread -pedantic -O3 -march=native -funroll-loops
#CFLAGS=-std=c99 -Wall -pthread -pedantic -O3 -msse4.2 -funroll-loops

SOURCE= \
blake2/blake2s.c \
hkdf/hkdf.c \
hkdf/hmac.c \
hkdf/sha1.c \
hkdf/sha224-256.c \
hkdf/sha384-512.c \
hkdf/usha.c \
twocats-common.c

OBJS=$(patsubst %.c,obj/%.o,$(SOURCE))

all: obj/blake2 obj/hkdf twocats-ref twocats twocats-test twocats-phs twocats-enc twocats-dec

-include $(OBJS:.o=.d)

twocats-ref: $(DEPS) $(OBJS) obj/main.o obj/twocats-ref.o
	$(CC) $(CFLAGS) $(OBJS) obj/main.o obj/twocats-ref.o -o twocats-ref

twocats: $(DEPS) $(OBJS) obj/main.o obj/twocats.o
	$(CC) $(CFLAGS) -pthread $(OBJS) obj/main.o obj/twocats.o -o twocats

twocats-test: $(DEPS) $(OBJS) obj/twocats-test.o obj/twocats-ref.o
	$(CC) $(CFLAGS) $(OBJS) obj/twocats-test.o obj/twocats-ref.o -o twocats-test

twocats-phs: $(DEPS) $(OBJS) obj/twocats-phs.o obj/twocats.o
	$(CC) $(CFLAGS) -pthread $(OBJS) obj/twocats-phs.o obj/twocats.o -o twocats-phs

twocats-enc: $(DEPS) $(OBJS) obj/twocats-enc.o obj/twocats.o
	$(CC) $(CFLAGS) -pthread $(OBJS) obj/twocats-enc.o obj/twocats.o -o twocats-enc -lssl -lcrypto

twocats-dec: $(DEPS) $(OBJS) obj/twocats-dec.o obj/twocats.o
	$(CC) $(CFLAGS) -pthread $(OBJS) obj/twocats-dec.o obj/twocats.o -o twocats-dec -lssl -lcrypto

clean:
	rm -rf obj twocats-ref twocats twocats-test twocats-phs twocats-enc twocats-dec

obj/blake2:
	mkdir -p obj/blake2

obj/hkdf:
	mkdir -p obj/hkdf

depend: clean
	@echo "* Making dependencies for $(OBJS)"
	@$(MAKE) -s $(OBJS)
	@echo "* Making dependencies - done"

obj/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) -MM $(CFLAGS) $< > obj/$*.d
	@cp -f obj/$*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> obj/$*.d
	@rm -f $*.d.tmp

