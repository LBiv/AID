.PHONY: all

## C sources are .c files in current directory 
C_SRCS = $(wildcard *.c)
OBJS = $(C_SRCS:.c=.o)

CFLAGS=-c -Wall

all: $(OBJS)
	@echo building all from $(C_SRCS) and $(OBJS)


$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -g -I../../include -o $@ $<

clean:
	rm $(OBJS)
