CFLAGS = -Wall -O3 -I.
ARCH ?= x86_64

OBJECTS := vmshell.o stage1/stage1.o

.PHONY: all stage1/stage1.o stage2-samples clean

all: vmshell stage2-samples

vmshell: $(OBJECTS)
	gcc $(CFLAGS) -o $@ $(OBJECTS)

stage1/stage1.o:
	make -C stage1 ARCH=$(ARCH) stage1.o

stage2-samples:
	make -C stage2 all

%.o: %.c
	gcc -c $(CFLAGS) -o $@ $<

clean:
	rm -f *.o vmshell
	make -C stage1 clean
	make -C stage2 clean
	make -C payload-libc clean
