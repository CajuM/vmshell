#define SHELL_VCPU_STACK_SIZE (1 << 16)
#define SHELL_CHILD_STACK_SIZE (1 << 21)

struct shell_state {
	void *shell_hook;
	size_t shell_len;

	struct shell_state *shell_self;

	void *shell_stage2_start;
	size_t shell_stage2_len;

	uint64_t *shell_vcpu_pml4;
	uint64_t *shell_vcpu_pdpt;

	void *shell_child_stack;

	void *shell_vcpu_stack;

	bool shell_locked;
	enum {
		SHELL_CMD_WAIT,
		SHELL_CMD_AGAIN,
		SHELL_CMD_CONT,
		SHELL_CMD_MMAP
	} shell_cmd;
	uint64_t shell_ret;
};
