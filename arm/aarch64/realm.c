#include "kvm/kvm.h"

#include "asm/realm.h"

static void kvm_arm_realm_create_realm_descriptor(struct kvm *kvm)
{
	struct kvm_enable_cap rme_create_rd = {
		.cap = KVM_CAP_ARM_RME,
		.args[0] = KVM_CAP_ARM_RME_CREATE_RD,
	};

	if (ioctl(kvm->vm_fd, KVM_ENABLE_CAP, &rme_create_rd) < 0)
		die_perror("KVM_CAP_RME(KVM_CAP_ARM_RME_CREATE_RD)");
}

static int kvm_arm_realm_finalize(struct kvm *kvm)
{
	if (!kvm__is_realm(kvm))
		return 0;

	kvm_arm_realm_create_realm_descriptor(kvm);

	return 0;
}
last_init(kvm_arm_realm_finalize)
