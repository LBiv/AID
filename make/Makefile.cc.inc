# common makefile to compile .c to .o in a directory
.PHONY: objs cleanobjs

## C sources are .c files in current directory 
C_SRCS = $(wildcard *.c) $(ADDL_SRCS)

OBJS = $(C_SRCS:.c=.o)

CFLAGS=-c -Wall

objs: $(OBJS)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -g $(CINC) -o $@ $<
	echo $@

cleanobjs:
	rm -f $(OBJS)
