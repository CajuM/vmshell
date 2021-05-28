.PHONY: clean

PWD := $(shell pwd)
PAYLOAD_LIBC := $(PWD)/../payload-libc
PAYLOAD_LIBC_OBJ := $(PAYLOAD_LIBC)/musl/obj

CFLAGS := -mgeneral-regs-only -fPIC -fno-stack-protector -O3 -Wall -U_FORTIFY_SOURCE
LDSCRIPT := stage1.lds
OBJECTS := entry.S.o stage1.c.o \
	$(PAYLOAD_LIBC_OBJ)/src/errno/__errno_location.lo \
	$(PAYLOAD_LIBC_OBJ)/src/misc/syscall.lo \
	$(PAYLOAD_LIBC_OBJ)/src/stdio/__toread.lo \
	$(PAYLOAD_LIBC_OBJ)/src/stdio/__uflow.lo \
	$(PAYLOAD_LIBC_OBJ)/src/stdlib/atoi.lo \
	$(PAYLOAD_LIBC_OBJ)/src/stdlib/strtol.lo \
	$(PAYLOAD_LIBC_OBJ)/src/string/memchr.lo \
	$(PAYLOAD_LIBC_OBJ)/src/string/memcmp.lo \
	$(PAYLOAD_LIBC_OBJ)/src/string/memcpy.lo \
	$(PAYLOAD_LIBC_OBJ)/src/string/memmove.lo \
	$(PAYLOAD_LIBC_OBJ)/src/string/strncmp.lo \
	$(PAYLOAD_LIBC_OBJ)/src/linux/clone.lo \
	$(PAYLOAD_LIBC_OBJ)/src/internal/intscan.lo \
	$(PAYLOAD_LIBC_OBJ)/src/internal/shgetc.lo \
	$(PAYLOAD_LIBC_OBJ)/src/internal/syscall_ret.lo \
	$(PAYLOAD_LIBC_OBJ)/src/thread/$(ARCH)/clone.lo

$(PAYLOAD_LIBC)/%.lo:
	make -C $(PAYLOAD_LIBC) ARCH=$(ARCH) $(subst $(PAYLOAD_LIBC_OBJ)/,,$@)

%.c.o: %.c
	gcc -c $(CFLAGS) -o $@ $<

%.S.o: %.S
	gcc -c $(CFLAGS) -o $@ $<

stage1.so: $(LDSCRIPT) $(OBJECTS)
	ld --gc-sections -T$(LDSCRIPT) -o $@ $(OBJECTS) -nostdlib

stage1.bin: stage1.so
	objcopy -O binary -j.stage1 $< $@

stage1.o: stage1.bin
	objcopy -I binary -O elf64-x86-64 $< $@

clean:
	rm -f *.o *.so *.bin
