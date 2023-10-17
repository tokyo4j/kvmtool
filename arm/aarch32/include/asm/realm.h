#ifndef __ASM_REALM_H_
#define __ASM_REALM_H_

#include "kvm/kvm.h"

struct kvm;

static inline bool kvm__is_realm(struct kvm *kvm)
{
	return false;
}

static inline void kvm_arm_realm_populate_ram(struct kvm *kvm,
					      unsigned long start,
					      unsigned long file_size,
					      unsigned long mem_size)
{
}

#endif
