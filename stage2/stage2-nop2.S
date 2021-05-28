.text

.globl _start


_start:
	push	%rax
	pushfq

	nop

	mov	%rsp, %rax
	add	$(128 + 3 * 8), %rax
	popfq
	mov	%rax, %rsp
	mov	-(128 + 2 * 8)(%rsp), %rax
	jmp	*-(128 + 8)(%rsp)
