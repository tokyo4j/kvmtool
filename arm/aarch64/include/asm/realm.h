#ifndef __ASM_REALM_H_
#define __ASM_REALM_H_

#include "kvm/kvm.h"

struct kvm;

static inline bool kvm__is_realm(struct kvm *kvm)
{
	return kvm->cfg.arch.is_realm;
}

void kvm_arm_realm_populate_ram(struct kvm *kvm, void *host_addr,
				unsigned long start,
				unsigned long file_size,
				enum kvm_image_type image_type);

void realm_log_rec(struct kvm *kvm, u64 flags, u64 pc, u64 gprs[8]);

uint64_t kvm_realm_reclaim_merged_page(struct kvm *kvm);

#endif
