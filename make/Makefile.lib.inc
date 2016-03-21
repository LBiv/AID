# common makefile for libraries

.PHONY: all

DEFAULT_LIBSTEM=$(notdir $(shell pwd))
LIBSTEM ?= $(DEFAULT_LIBSTEM)
TGT_STATIC_LIB ?= lib$(LIBSTEM).a

MAKEFILE_DIR = $(dir $(lastword $(MAKEFILE_LIST)))

all: $(TGT_STATIC_LIB)
	@echo building all from $(C_SRCS) and $(OBJS)
	@echo  "lib  stem: " $(LIBSTEM)


include $(MAKEFILE_DIR)Makefile.cc.inc

$(TGT_STATIC_LIB): $(OBJS)
	@echo "HERE"
	ar r $@ $?
	@echo $?
	@echo $?

clean: cleanobjs
	rm -f $(TGT_STATIC_LIB)
