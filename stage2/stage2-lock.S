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

	mov	$1, %rdi
	mov	$1, %rsi
	call	lock

exit:
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


lock:
	push	%r14
	push	%r15

	push	%rbx

	mov	$0x67390a7494d83aa4, %r14
	mov	$0x8bdb9683da40e963, %r15

lock_loop:
	mov	$0x4cd50e8423beddbc, %rbx
	cmp	%rbx, %r14
	jne	lock_loop

	mov	$0x44b58a6971bca587, %rbx
	cmp	%rbx, %r15
	jne	lock_loop

lock_end:
	pop	%rbx

	pop	%r15
	pop	%r14

	ret
