# Makefile for twocats

DEPS = Makefile

CC=gcc
# Use this for the normal release, unless you must support older machines
CFLAGS=-std=c99 -Wall -pthread -pedantic -O3 -march=native -funroll-loops
# Use this for debugging
#CFLAGS=-std=c99 -Wall -pthread -pedantic -g -march=native
# Use this for older machines that don't support SSE
#CFLAGS=-std=c99 -Wall -pthread -pedantic -O3 -march=i686 -m32 -funroll-loops
LIBS=-lcrypto

SOURCE= \
twocats-common.c \
twocats-blake2s.c \
twocats-blake2b.c \
twocats-sha256.c \
twocats-sha512.c

REF_SOURCE=main.c twocats-ref.c
TWOCATS_SOURCE=main.c twocats.c
#TEST_SOURCE=twocats-test.c twocats-ref.c
TEST_SOURCE=twocats-test.c twocats.c
PHS_SOURCE=twocats-phs.c twocats.c
ENC_SOURCE=twocats-enc.c twocats.c
DEC_SOURCE=twocats-dec.c twocats.c

OBJS=$(patsubst %.c,obj/%.o,$(SOURCE))
REF_OBJS=$(patsubst %.c,obj/%.o,$(REF_SOURCE))
TWOCATS_OBJS=$(patsubst %.c,obj/%.o,$(TWOCATS_SOURCE))
TEST_OBJS=$(patsubst %.c,obj/%.o,$(TEST_SOURCE))
PHS_OBJS=$(patsubst %.c,obj/%.o,$(PHS_SOURCE))
ENC_OBJS=$(patsubst %.c,obj/%.o,$(ENC_SOURCE))
DEC_OBJS=$(patsubst %.c,obj/%.o,$(DEC_SOURCE))

all: obj twocats-ref twocats twocats-test twocats-phs twocats-enc twocats-dec

-include $(OBJS:.o=.d) $(REF_OBJS:.o=.d) $(TWOCATS_OBJS:.o=.d) $(PHS_OBJS:.o=.d) $(ENC_OBJS:.o=.d) $(DEC_OBJS:.o=.d)

twocats-ref: $(DEPS) $(OBJS) $(REF_OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(REF_OBJS) -o twocats-ref $(LIBS)

twocats: $(DEPS) $(OBJS) $(TWOCATS_OBJS)
	$(CC) $(CFLAGS) -pthread $(OBJS) $(TWOCATS_OBJS) -o twocats $(LIBS)

twocats-test: $(DEPS) $(OBJS) $(TEST_OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(TEST_OBJS) -o twocats-test $(LIBS)

twocats-phs: $(DEPS) $(OBJS) $(PHS_OBJS)
	$(CC) $(CFLAGS) -pthread $(OBJS) $(PHS_OBJS) -o twocats-phs $(LIBS)

twocats-enc: $(DEPS) $(OBJS) $(ENC_OBJS)
	$(CC) $(CFLAGS) -pthread $(OBJS) $(ENC_OBJS) -o twocats-enc -lssl -lcrypto

twocats-dec: $(DEPS) $(OBJS) $(DEC_OBJS)
	$(CC) $(CFLAGS) -pthread $(OBJS) $(DEC_OBJS) -o twocats-dec -lssl -lcrypto

clean:
	rm -rf obj twocats-ref twocats twocats-test twocats-phs twocats-enc twocats-dec

obj:
	mkdir obj

obj/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) -MM $(CFLAGS) $< | sed 's|^.*:|$@:|' > $(patsubst %.o,%.d,$@)

