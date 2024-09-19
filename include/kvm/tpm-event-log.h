/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef TPM_EVENT_LOG_H_
#define TPM_EVENT_LOG_H_

#include <stddef.h>
#include <linux/types.h>

/*
 * Defined in TCG Algorithm Registry
 * Family 2.0 Level 00 Revision 01.34
 */
#define TPM_ALG_SHA256	0xB
#define TPM_ALG_SHA512	0xD

/* Size of a digest in bytes */
#define TPM_ALG_SHA256_DIGEST_SIZE	32
#define TPM_ALG_SHA512_DIGEST_SIZE	64

/*
 * Defined in TCG PC Client Platform Firmware Profile Specification
 * Version 1.06 revision 52
 */
#define TCG_EV_NO_ACTION			0x00000003
#define TCG_EV_EVENT_TAG			0x00000006
#define TCG_EV_POST_CODE2			0x00000013
#define TCG_EV_EFI_PLATFORM_FIRMWARE_BLOB2	0x8000000A

enum event_log_hash_algo {
	EVENT_LOG_HASH_SHA256,
	EVENT_LOG_HASH_SHA512,
};

#ifdef CONFIG_HAS_EVENT_LOG

/**
 * Initialize the event log.
 *
 * @base: buffer allocated in guest memory
 * @max_size: size of the buffer
 * @hash_algo: algorithm used to produce the event digests
 *
 * For the moment, a single hash algorithm is used, meaning the log header
 * declares only this algorithm, and UEFI won't be able to use a different
 * algorithm to extend the log (unless it rewrites all entries, since some
 * entry sizes depend on all declared algos).
 */
int tpm_event_log_init(void *base, size_t max_size,
		       enum event_log_hash_algo hash_algo);

/**
 * Extend the log with a new event.
 *
 * @event_type: A TCG_EV_* event type
 * @event: event data. Note that numerical fields must be little-endian.
 * @event_size: size of @event
 * @data: optional data to hash
 * @data_size: size of the data
 */
int tpm_event_log_add(u32 event_type, const u8 *event, size_t event_size,
		      const u8 *data, size_t data_size);

/**
 * Extend the log with a new event, an image blob.
 * @image_type: type of the image loaded into guest mem
 * @host_addr: address of the blob
 * @base: address in guest memory
 * @size: size of the blob
 */
int tpm_event_log_add_image(enum kvm_image_type image_type, const u8 *host_addr,
			    u64 base, size_t size);

/**
 * Get the current log length in bytes
 */
size_t tpm_event_log_length(void);

/**
 * Free data allocated for generating the event log.
 */
void tpm_event_log_close(void);

#else /* CONFIG_HAS_EVENT_LOG */

static inline int tpm_event_log_init(void *base, size_t max_size,
				     enum event_log_hash_algo hash_algo)
{
	return -ENODEV;
}

static inline int tpm_event_log_add(u32 event_type, const u8 *event,
				   size_t event_size, const u8 *data,
				   size_t data_size)
{
	return -ENODEV;
}

static inline int tpm_event_log_add_image(enum kvm_image_type image_type,
					  const u8 *host_addr, u64 base,
					  size_t size)
{
	return -ENODEV;
}

static inline size_t tpm_event_log_length(void)
{
	return 0;
}

static inline void tpm_event_log_close(void) {}

#endif /* CONFIG_HAS_EVENT_LOG */
#endif /* TPM_EVENT_LOG_H_ */
