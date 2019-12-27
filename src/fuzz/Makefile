# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

all: config

CFLAGS ?= -O3 -march=native -g
CFLAGS += -fsanitize=fuzzer -std=gnu11 -idirafter ../uapi

config: config.c ../config.c ../encoding.c
	clang $(CFLAGS) -o $@ $<

clean:
	rm -f config

.PHONY: all clean
