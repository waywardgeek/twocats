# Makefile for TigerPHS code examples

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

all: tigerphs-ref tigerphs tigerphs-test tigerphs-phs
#all: tigerphs-ref tigerphs tigerphs-test tigerphs-phs tigerphs-enc tigerphs-dec

-include $(OBJS:.o=.d)

tigerphs-ref: $(DEPS) $(OBJS) main.c tigerphs-ref.c tigerphs-impl.h tigerphs.h
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) $(OBJS) main.c tigerphs-ref.c -o tigerphs-ref

tigerphs: $(DEP) $(OBJS) main.c tigerphs.c tigerphs.h tigerphs-impl.h
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) -pthread $(OBJS) main.c tigerphs.c -o tigerphs

tigerphs-test: $(DEPS) $(OBJS) tigerphs-test.c tigerphs-ref.c tigerphs.h tigerphs-impl.h
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) $(OBJS) tigerphs-test.c tigerphs-ref.c -o tigerphs-test

tigerphs-phs: $(DEPS) $(OBJS) tigerphs-phs.c tigerphs.c tigerphs.h tigerphs-impl.h
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) -pthread $(OBJS) tigerphs-phs.c tigerphs.c -o tigerphs-phs

tigerphs-enc: $(DEPS) $(OBJS) tigerphs-enc.c tigerphs.c tigerphs.h tigerphs-impl.h
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) -pthread $(OBJS) tigerphs-enc.c tigerphs.c -o tigerphs-enc -lssl -lcrypto

tigerphs-dec: $(DEPS) $(OBJS) tigerphs-dec.c tigerphs.c tigerphs.h tigerphs-impl.h
	@echo "* Compiling $@";
	@$(CC) $(CFLAGS) -pthread $(OBJS) tigerphs-dec.c tigerphs.c -o tigerphs-dec -lssl -lcrypto

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
	@$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) -MM $(CFLAGS) $< > obj/$*.d
	@cp -f obj/$*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> obj/$*.d
	@rm -f $*.d.tmp

