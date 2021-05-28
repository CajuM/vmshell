.text

.globl _entry

_entry:
	.rept 20
	nop
	.endr

	pushfq
	push %rbp
	push %rax
	push %rbx
	push %rcx
	push %rdx
	push %rsi
	push %rdi
	push %r8
	push %r9
	push %r10
	push %r11
	push %r12
	push %r13
	push %r14
	push %r15

	lea _stage1_end(%rip), %rdi
	jmp start_c
