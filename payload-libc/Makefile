.PHONY: clean out

PWD := $(shell pwd)

CFLAGS := -mgeneral-regs-only -fPIC -fno-stack-protector -O3 -Wno-parentheses -U_FORTIFY_SOURCE

musl/config.mak:
	cd musl && CFLAGS="$(CFLAGS)" ./configure

src/errno/__errno_location.lo: __errno_location.c
	mkdir -p musl/obj/src/errno
	gcc -c $(CFLAGS) -o musl/obj/$@ $<

%.lo: musl/config.mak
	make -C musl obj/$@

clean:
	make -C musl distclean
