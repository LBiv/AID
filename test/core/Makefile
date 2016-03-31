TEST_PGM = test_$(notdir $(shell pwd))

test: $(TEST_PGM)
	@echo $(TEST_PGM)
	@echo $(PHONYTGTS)
	@echo $(SRC_SUBDIRS)
	@echo $(SUB_LIBS)

SRC_DEPS = core


SUBDIRS = ../../src/core
SUB_LIBS = -L ../../src/core -lcore
#SUB_LIBS=$(patsubst %,%/lib$(notdir %%).a,$(SUBDIRS))
PHONYTGTS=$(foreach SUBDIR,$(SUBDIRS),$(notdir $(SUBDIR)))
LIB_CHECK=/usr/lib/libcheck.so

.PHONY: $(PHONYTGTS)

CINC=-I. -I../../include


include ../../make/Makefile.test.inc


$(TEST_PGM): $(SRC_DEPS) $(OBJS)
	gcc -o $@ $(OBJS) $(SUB_LIBS) $(LIB_CHECK)

#@$(SRC_DEPS): %: ../../src/%:
#@	$(MAKE) -C $<
#@
#@$(DEPS_DEPS): %: ../../deps/%:
#@	$(MAKE) -C $<

core:
	$(MAKE) -C $(patsubst %,../../src/%,$@)
