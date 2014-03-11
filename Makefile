# Makefile for TigerPHS code examples

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
tigerphs-common.c

OBJS=$(patsubst %.c,obj/%.o,$(SOURCE))

all: obj/blake2 obj/hkdf tigerphs-ref tigerphs tigerphs-test tigerphs-phs tigerphs-enc tigerphs-dec

-include $(OBJS:.o=.d)

tigerphs-ref: $(DEPS) $(OBJS) obj/main.o obj/tigerphs-ref.o
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) $(OBJS) obj/main.o obj/tigerphs-ref.o -o tigerphs-ref

tigerphs: $(DEPS) $(OBJS) obj/main.o obj/tigerphs.o
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) -pthread $(OBJS) obj/main.o obj/tigerphs.o -o tigerphs

tigerphs-test: $(DEPS) $(OBJS) obj/tigerphs-test.o obj/tigerphs-ref.o
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) $(OBJS) obj/tigerphs-test.o obj/tigerphs-ref.o -o tigerphs-test

tigerphs-phs: $(DEPS) $(OBJS) obj/tigerphs-phs.o obj/tigerphs.o
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) -pthread $(OBJS) obj/tigerphs-phs.o obj/tigerphs.o -o tigerphs-phs

tigerphs-enc: $(DEPS) $(OBJS) obj/tigerphs-enc.o obj/tigerphs.o
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) -pthread $(OBJS) obj/tigerphs-enc.o obj/tigerphs.o -o tigerphs-enc -lssl -lcrypto

tigerphs-dec: $(DEPS) $(OBJS) obj/tigerphs-dec.o obj/tigerphs.o
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) -pthread $(OBJS) obj/tigerphs-dec.o obj/tigerphs.o -o tigerphs-dec -lssl -lcrypto

clean:
	rm -rf obj tigerphs-ref tigerphs tigerphs-test tigerphs-phs tigerphs-enc tigerphs-dec

obj/blake2:
	@mkdir -p obj/blake2

obj/hkdf:
	@mkdir -p obj/hkdf

depend: clean
	@echo "* Making dependencies for $(OBJS)"
	@$(MAKE) -s $(OBJS)
	@echo "* Making dependencies - done"

obj/%.o: %.c
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) -MM $(CFLAGS) $< > obj/$*.d
	@cp -f obj/$*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> obj/$*.d
	@rm -f $*.d.tmp

