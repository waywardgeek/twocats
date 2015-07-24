# Makefile for twocats

DEPS = Makefile

CC=gcc

# Use this for the normal release, unless you must support older machines
CFLAGS=-std=c99 -Wall -pedantic -O3 -march=native -funroll-loops -I ../src

# Use this for debugging
#CFLAGS=-std=c99 -Wall -pedantic -g -march=native

# Use this for older machines that don't support SSE
#CFLAGS=-std=c99 -Wall -pedantic -O3 -march=i686 -m32 -funroll-loops

LIBS=-lcrypto

MAIN_SOURCE=main.c
ENC_SOURCE=twocats-enc.c
DEC_SOURCE=twocats-dec.c

MAIN_OBJS=$(patsubst %.c,obj/%.o,$(MAIN_SOURCE))
ENC_OBJS=$(patsubst %.c,obj/%.o,$(ENC_SOURCE))
DEC_OBJS=$(patsubst %.c,obj/%.o,$(DEC_SOURCE))

all: obj twocats-ref twocats-opt twocats-enc twocats-dec

-include $(MAIN_OBJS:.o=.d) $(ENC_OBJS:.o=.d) $(DEC_OBJS:.o=.d)

twocats-ref: $(DEPS) $(MAIN_OBJS)
	$(CC) $(CFLAGS) $(MAIN_OBJS) -o twocats-ref ../src/libtwocats-ref.a $(LIBS)

twocats-opt: $(DEPS) $(MAIN_OBJS)
	$(CC) $(CFLAGS) -pthread $(MAIN_OBJS) -o twocats-opt ../src/libtwocats.a $(LIBS)

twocats-enc: $(DEPS) $(ENC_OBJS)
	$(CC) $(CFLAGS) -pthread $(ENC_OBJS) -o twocats-enc ../src/libtwocats.a -lssl $(LIBS)

twocats-dec: $(DEPS) $(DEC_OBJS)
	$(CC) $(CFLAGS) -pthread $(DEC_OBJS) -o twocats-dec ../src/libtwocats.a -lssl $(LIBS)

clean:
	rm -rf obj twocats-ref twocats-opt twocats-enc twocats-dec

obj:
	mkdir obj

obj/%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) -MM $(CFLAGS) $< | sed 's|^.*:|$@:|' > $(patsubst %.o,%.d,$@)

