#ifndef __ARM_PMU_H__
#define __ARM_PMU_H__

#define KVM_ARM_PMUv3_PPI			23

#define ARMV8_PMU_PMCR_N_SHIFT			11
#define ARMV8_PMU_PMCR_N_MASK			0x1f

void pmu__generate_fdt_nodes(void *fdt, struct kvm *kvm);

#endif /* __ARM_PMU_H__ */
