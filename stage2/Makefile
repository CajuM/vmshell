.PHONY: all clean

PWD := $(shell pwd)

CFLAGS := -mgeneral-regs-only -fPIC -fno-stack-protector -O3 -Wall -Werror -U_FORTIFY_SOURCE
LDFLAGS := -static -fPIE -nostdlib

all: stage2.bin stage2-nop.bin stage2-nop2.bin stage2-lock.bin

%.S.o: %.S
	gcc -c $(CFLAGS) -o $@ $<

%.bin: %.so
	objcopy -O binary -j.text $< $@

%.so: %.S.o
	gcc $(LDFLAGS) -o $@ $<

clean:
	rm -f *.o *.so *.bin
