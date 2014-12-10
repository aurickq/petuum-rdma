# Assuming this Makefile lives in project root directory
PROJECT := $(shell readlink $(dir $(lastword $(MAKEFILE_LIST))) -f)

PETUUM_ROOT = $(PROJECT)

include $(PROJECT)/defns.mk

# defined in defns.mk
SRC = $(PETUUM_SRC)
LIB = $(PETUUM_LIB)
THIRD_PARTY = $(PETUUM_THIRD_PARTY)
THIRD_PARTY_SRC = $(PETUUM_THIRD_PARTY_SRC)
THIRD_PARTY_LIB = $(PETUUM_THIRD_PARTY_LIB)
THIRD_PARTY_INCLUDE = $(PETUUM_THIRD_PARTY_INCLUDE)

BIN = $(PROJECT)/bin

NEED_MKDIR = $(BIN) \
             $(LIB) \
             $(TESTS_BIN) \
             $(THIRD_PARTY_SRC) \
             $(THIRD_PARTY_LIB) \
             $(THIRD_PARTY_INCLUDE)

CXX = rc --compile 
CXXFLAGS = $(PETUUM_CXXFLAGS)
CXXFLAGS += -DPETUUM_MAX_NUM_CLIENTS=8
INCFLAGS = $(PETUUM_INCFLAGS)
LDFLAGS = $(PETUUM_LDFLAGS)

all: path \
     ps_lib \
     ps_sn_lib

path: $(NEED_MKDIR)

$(NEED_MKDIR):
	mkdir -p $@

.PHONY: all path clean distclean

include $(SRC)/petuum.mk
