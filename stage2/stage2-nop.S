.text

.globl _start


_start:
	pushfq

	push	%rax

	push	%rcx
	push	%r11

	push	%rdi
	push	%rsi
	push	%rdx
	push	%r10
	push	%r9
	push	%r8

	nop

	pop	%r8
	pop	%r9
	pop	%r10
	pop	%rdx
	pop	%rsi
	pop	%rdi

	pop	%r11
	pop	%rcx

	pop	%rax

	popfq

	ret
