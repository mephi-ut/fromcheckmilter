
LDFLAGS = -lmilter -L/usr/lib/libmilter/
INCFLAGS = 
CFLAGS += -pipe -Wall -pedantic -O2 -fstack-protector-all
DEBUGCFLAGS = -pipe -Wall -pedantic -Werror -ggdb -Wno-error=unused-variable -fstack-protector-all

objs=\
main.o\


all: $(objs)
	$(CC) $(CFLAGS) $(LDFLAGS) $(objs) -o from-check-milter

%.o: %.c
	$(CC) -std=gnu11 $(CFLAGS) $(INCFLAGS) $< -c -o $@

debug:
	$(CC) -std=gnu11 $(DEBUGCFLAGS) $(INCFLAGS) $(LDFLAGS) *.c -o from-check-milter-debug

clean:
	rm -f from-check-milter from-check-milter-debug $(objs)


