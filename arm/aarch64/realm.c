#include <linux/list.h>
#include "kvm/kvm.h"

#include "asm/realm.h"

struct realm_ram_region {
	u64 start;
	u64 file_end;
	u64 mem_end;
	struct list_head list;
};

static LIST_HEAD(realm_ram_regions);

static void realm_configure_hash_algo(struct kvm *kvm)
{
	struct kvm_cap_arm_rme_config_item hash_algo_cfg = {
		.cfg	= KVM_CAP_ARM_RME_CFG_HASH_ALGO,
		.hash_algo = kvm->arch.measurement_algo,
	};

	struct kvm_enable_cap rme_config = {
		.cap = KVM_CAP_ARM_RME,
		.args[0] = KVM_CAP_ARM_RME_CONFIG_REALM,
		.args[1] = (u64)&hash_algo_cfg,
	};

	if (ioctl(kvm->vm_fd, KVM_ENABLE_CAP, &rme_config) < 0)
		die_perror("KVM_CAP_RME(KVM_CAP_ARM_RME_CONFIG_REALM) hash_algo");
}

static void realm_configure_rpv(struct kvm *kvm)
{
	struct kvm_cap_arm_rme_config_item rpv_cfg  = {
		.cfg	= KVM_CAP_ARM_RME_CFG_RPV,
	};

	struct kvm_enable_cap rme_config = {
		.cap = KVM_CAP_ARM_RME,
		.args[0] = KVM_CAP_ARM_RME_CONFIG_REALM,
		.args[1] = (u64)&rpv_cfg,
	};

	if (!kvm->cfg.arch.realm_pv)
		return;

	memset(&rpv_cfg.rpv, 0, sizeof(rpv_cfg.rpv));
	memcpy(&rpv_cfg.rpv, kvm->cfg.arch.realm_pv, strlen(kvm->cfg.arch.realm_pv));

	if (ioctl(kvm->vm_fd, KVM_ENABLE_CAP, &rme_config) < 0)
		die_perror("KVM_CAP_RME(KVM_CAP_ARM_RME_CONFIG_REALM) RPV");
}

static void realm_configure_parameters(struct kvm *kvm)
{
	realm_configure_hash_algo(kvm);
	realm_configure_rpv(kvm);
}

static void kvm_arm_realm_create_realm_descriptor(struct kvm *kvm)
{
	struct kvm_enable_cap rme_create_rd = {
		.cap = KVM_CAP_ARM_RME,
		.args[0] = KVM_CAP_ARM_RME_CREATE_RD,
	};

	realm_configure_parameters(kvm);
	if (ioctl(kvm->vm_fd, KVM_ENABLE_CAP, &rme_create_rd) < 0)
		die_perror("KVM_CAP_RME(KVM_CAP_ARM_RME_CREATE_RD)");
}

static void realm_init_ipa_range(struct kvm *kvm, u64 start, u64 size)
{
	struct kvm_cap_arm_rme_init_ipa_args init_ipa_args = {
		.init_ipa_base = start,
		.init_ipa_size = size
	};
	struct kvm_enable_cap rme_init_ipa_realm = {
		.cap = KVM_CAP_ARM_RME,
		.args[0] = KVM_CAP_ARM_RME_INIT_IPA_REALM,
		.args[1] = (u64)&init_ipa_args
	};

	if (ioctl(kvm->vm_fd, KVM_ENABLE_CAP, &rme_init_ipa_realm) < 0)
		die("unable to intialise IPA range for Realm %llx - %llx (size %llu)",
		    start, start + size, size);
	pr_debug("Initialized IPA range (%llx - %llx) as RAM\n",
		start, start + size);
}

static void __realm_populate(struct kvm *kvm, u64 start, u64 size)
{
	struct kvm_cap_arm_rme_populate_realm_args populate_args = {
		.populate_ipa_base = start,
		.populate_ipa_size = size,
		.flags		   = KVM_ARM_RME_POPULATE_FLAGS_MEASURE,
	};
	struct kvm_enable_cap rme_populate_realm = {
		.cap = KVM_CAP_ARM_RME,
		.args[0] = KVM_CAP_ARM_RME_POPULATE_REALM,
		.args[1] = (u64)&populate_args
	};

	if (ioctl(kvm->vm_fd, KVM_ENABLE_CAP, &rme_populate_realm) < 0)
		die("unable to populate Realm memory %llx - %llx (size %llu)",
		    start, start + size, size);
	pr_debug("Populated Realm memory area : %llx - %llx (size %llu bytes)",
		start, start + size, size);
}

static void realm_populate(struct kvm *kvm, struct realm_ram_region *region)
{
	__realm_populate(kvm, region->start,
			 region->file_end - region->start);
	/*
	 * Mark the unpopulated areas of the kernel image as
	 * RAM explicitly.
	  */
	if (region->file_end < region->mem_end)
		realm_init_ipa_range(kvm, region->file_end,
				     region->mem_end - region->file_end);
}

void kvm_arm_realm_populate_ram(struct kvm *kvm, unsigned long start,
				unsigned long file_size,
				unsigned long mem_size)
{
	struct realm_ram_region *new_region;

	new_region = calloc(1, sizeof(*new_region));
	if (!new_region)
		die("cannot allocate realm RAM region");

	new_region->start = ALIGN_DOWN(start, SZ_4K);
	new_region->file_end = ALIGN(start + file_size, SZ_4K);
	new_region->mem_end = ALIGN(start + mem_size, SZ_4K);

	list_add_tail(&new_region->list, &realm_ram_regions);
}

static int kvm_arm_realm_finalize(struct kvm *kvm)
{
	struct realm_ram_region *region, *next;

	if (!kvm__is_realm(kvm))
		return 0;

	kvm_arm_realm_create_realm_descriptor(kvm);

	list_for_each_entry_safe(region, next, &realm_ram_regions, list) {
		realm_populate(kvm, region);
		list_del(&region->list);
		free(region);
	}

	return 0;
}
last_init(kvm_arm_realm_finalize)
