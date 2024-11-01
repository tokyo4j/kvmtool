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
					      unsigned long file_size)
{
}

static inline void realm_log_rec(struct kvm *kvm, u64 flags, u64 pc, u64
				 gprs[8])
{
}

#endif
