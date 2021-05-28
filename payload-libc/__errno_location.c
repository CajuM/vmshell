#include "musl/src/include/features.h"

int *__errno_location(void)
{
	static int errno_val;
	return &errno_val;
}

weak_alias(__errno_location, ___errno_location);
