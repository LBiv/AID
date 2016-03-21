# common makefile for test

.PHONY: test build

MAKEFILE_DIR = $(dir $(lastword $(MAKEFILE_LIST)))
include $(MAKEFILE_DIR)Makefile.cc.inc
