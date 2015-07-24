# Makefile for twocats

DEPS = Makefile

CC=gcc

# Use this for the normal release, unless you must support older machines
CFLAGS=-std=c99 -Wall -pedantic -O3 -march=native -funroll-loops

# Use this for debugging
#CFLAGS=-std=c99 -Wall -pedantic -g -march=native

# Use this for older machines that don't support SSE
#CFLAGS=-std=c99 -Wall -pedantic -O3 -march=i686 -m32 -funroll-loops

LIBS=-lcrypto

SOURCE= \
twocats-common.c \
twocats-blake2s.c \
twocats-blake2b.c \
twocats-sha256.c \
twocats-sha512.c

TEST_SOURCE=twocats-test.c twocats-ref.c
#TEST_SOURCE=twocats-test.c twocats-opt.c

OBJS=$(patsubst %.c,obj/%.o,$(SOURCE))
TEST_OBJS=$(patsubst %.c,obj/%.o,$(TEST_SOURCE))

all: obj twocats-test libtwocats.a libtwocats-ref.a

-include $(OBJS:.o=.d) $(REF_OBJS:.o=.d) $(TWOCATS_OBJS:.o=.d) $(ENC_OBJS:.o=.d) $(DEC_OBJS:.o=.d)

twocats-test: $(DEPS) $(OBJS) $(TEST_OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(TEST_OBJS) -o twocats-test $(LIBS)
	@#$(CC) $(CFLAGS) $(OBJS) $(TEST_OBJS) -pthread -o twocats-test $(LIBS)

libtwocats.a: $(DEPS) $(OBJS) obj/twocats-opt.o
	ar rcs libtwocats.a $(OBJS) obj/twocats-opt.o

libtwocats-ref.a: $(DEPS) $(OBJS) obj/twocats-ref.o
	ar rcs libtwocats-ref.a $(OBJS) obj/twocats-ref.o

clean:
	rm -rf obj twocats-test twocats.o libtwocats.a libtwocats-ref.a

obj:
	mkdir obj

obj/%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) -MM $(CFLAGS) $< | sed 's|^.*:|$@:|' > $(patsubst %.o,%.d,$@)

