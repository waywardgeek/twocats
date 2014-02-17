pebble: pedatabase.c pedatabase.h main.c
	gcc -Wall -g -DDD_DEBUG pedatabase.c main.c -o pebble -lm -lddutil-dbg

pedatabase.h: pedatabase.c

pedatabase.c: Pebble.dd
	datadraw Pebble.dd

clean:
	rm pebble
