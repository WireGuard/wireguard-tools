# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2018-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

all: config uapi stringlist

CFLAGS ?= -O3 -march=native -g
CFLAGS += -fsanitize=fuzzer -fsanitize=address -std=gnu11 -idirafter ../uapi
CC := clang

config: config.c ../config.c ../encoding.c
	$(CC) $(CFLAGS) -o $@ $<

uapi: uapi.c ../ipc.c ../curve25519.c ../encoding.c
	$(CC) $(CFLAGS) -o $@ $<

stringlist: stringlist.c ../ipc.c ../curve25519.c ../encoding.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f config uapi stringlist

.PHONY: all clean
