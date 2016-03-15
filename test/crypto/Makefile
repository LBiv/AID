.PHONY: all

#.c.o:

# cancel built-in implicit rules
#.c.o:
#	echo .o .c from $< >$@
#
## C sources are .c files in current directory 
C_SRCS = $(wildcard *.c)
OBJS = $(C_SRCS:.c=.o)

all: $(OBJS)
	@echo building all from $(C_SRCS) and $(OBJS)


$(OBJS): %.o: %.c
	$(CC) -c -g -I../../include -o $@ $<

#
#all : $(C_SRCS)
#echo $(C_SRCS)

