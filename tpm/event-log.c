/* SPDX-License-Identifier: GPL-2.0+ */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <linux/byteorder.h>
#include <linux/compiler.h>
#include <linux/types.h>

#include "kvm/kvm.h"
#include "kvm/tpm-event-log.h"

#include <openssl/evp.h>
#include <openssl/err.h>

/*
 * Legacy structure used only in the first event in the log, for compatibility
 */
struct tcg_pc_client_pcr_event {
	__le32	pcr_index;
	__le32	event_type;
	u8	digest[20];
	__le32	event_data_size;
	u8	event[];
} __packed;

struct tcg_efi_spec_id_event {
	u8	signature[16];
	__le32	platform_class;
	u8	family_version_minor;
	u8	family_version_major;
	u8	spec_revision;
	u8	uintn_size;
	__le32	number_of_algorithms; /* 1 */
	/* For now we declare a single algo */
	__le16	algorithm_id;
	__le16	digest_size;
	u8	vendor_info_size;
	u8	vendor_info[];
} __packed;

/*
 * The event2 structure contains variable-size digests in the middle.
 */
struct tcg_pcr_event2_head {
	__le32	pcr_index;
	__le32	event_type;
	u8	digests[];
} __packed;

struct tcg_pcr_event2_tail {
	__le32	event_size;
	u8	event[];
} __packed;

struct tpml_digest_values {
	__le32	count;		/* 1 */
	__le16	hash_alg;
	u8	digest[];
} __packed;

struct uefi_platform_firmware_blob2_head {
	u8	blob_description_size;
	u8	blob_description[];
} __packed;

struct uefi_platform_firmware_blob2_tail {
	__le64	blob_base;
	__le64	blob_size;
} __packed;

static void *log_base;
static size_t log_size;
static size_t log_max_size;
static u16 log_algo_id;
static size_t log_digest_size;

static EVP_MD_CTX *hash_context;
static EVP_MD *hash_func;

static int init_hash_func(const char *libcrypto_func)
{
	hash_context = EVP_MD_CTX_new();
	if (!hash_context)
		return 1;

	hash_func = EVP_MD_fetch(NULL, libcrypto_func, NULL);
	if (!hash_func) {
		EVP_MD_CTX_free(hash_context);
		return 1;
	}

	return 0;
}

static int digest_buffer(void *output, const u8 *buf, size_t size)
{
	assert(hash_context && hash_func);
	if (!EVP_DigestInit_ex(hash_context, hash_func, NULL))
		return -EINVAL;

	if (!EVP_DigestUpdate(hash_context, buf, size))
		return -EIO;

	if (!EVP_DigestFinal_ex(hash_context, output, NULL))
		return -EIO;

	return 0;
}

int tpm_event_log_init(void *base, size_t max_size,
		       enum event_log_hash_algo hash_algo)
{
	const char *libcrypto_func;
	struct tcg_pc_client_pcr_event *hdr;
	struct tcg_efi_spec_id_event *event;

	log_base = base;
	log_size = 0;
	log_max_size = max_size;

	if (log_max_size < sizeof(*hdr) + sizeof(*event))
		return -ENOSPC;

	switch(hash_algo) {
	case EVENT_LOG_HASH_SHA256:
		log_algo_id = TPM_ALG_SHA256;
		log_digest_size = TPM_ALG_SHA256_DIGEST_SIZE;
		libcrypto_func = "SHA256";
		break;
	case EVENT_LOG_HASH_SHA512:
		log_algo_id = TPM_ALG_SHA512;
		log_digest_size = TPM_ALG_SHA512_DIGEST_SIZE;
		libcrypto_func = "SHA512";
		break;
	default:
		return -EINVAL;
	}

	if (init_hash_func(libcrypto_func)) {
		ERR_print_errors_fp(stderr);
		return -ESRCH;
	}

	hdr = log_base;
	*hdr = (struct tcg_pc_client_pcr_event) {
		.pcr_index = 0,
		.event_type = cpu_to_le32(TCG_EV_NO_ACTION),
		.digest = {0},
		.event_data_size = cpu_to_le32(sizeof(*event)),
	};
	log_size += sizeof(*hdr);

	event = log_base + log_size;
	*event = (struct tcg_efi_spec_id_event) {
		.signature = "Spec ID Event03",
		.platform_class = 0,
		.family_version_minor = 0,
		.family_version_major = 2,
		.spec_revision = 106,
		.uintn_size = 2, /* UINT64 */
		.number_of_algorithms = cpu_to_le32(1),
		.algorithm_id = cpu_to_le16(log_algo_id),
		.digest_size = cpu_to_le16(log_digest_size),
		.vendor_info_size = 0,
	};
	log_size += sizeof(*event);

	return 0;
}

int tpm_event_log_add(u32 event_type, const u8 *event, size_t event_size,
		      const u8 *data, size_t data_size)
{
	size_t saved_size;
	u32 digest_count = 0;
	struct tcg_pcr_event2_head *head;
	struct tcg_pcr_event2_tail *tail;
	struct tpml_digest_values *digest;

	if (log_max_size < log_size +
	    sizeof(*head) + sizeof(*tail) +
	    sizeof(*digest) + log_digest_size +
	    event_size)
		return -ENOSPC;

	saved_size = log_size;
	head = log_base + log_size;
	head->pcr_index = 0;
	head->event_type = cpu_to_le32(event_type);
	log_size += sizeof(*head);

	digest = (void *)head->digests;
	if (data) {
		digest_count = 1;
		digest->hash_alg = cpu_to_le16(log_algo_id);
		if (digest_buffer(digest->digest, data, data_size)) {
			ERR_print_errors_fp(stderr);
			log_size = saved_size;
			return -EIO;
		}
	} else if (event_type == TCG_EV_NO_ACTION) {
		/* For EV_NO_ACTION, empty digests for each algo */
		digest_count = 1;
		digest->hash_alg = 0;
		memset(digest->digest, 0, log_digest_size);
	}
	// FIXME: is an event without digest valid? Or do we need a zero sha256
	// digest? Except for EV_NO_ACTION above, the parser needs a digest type
	// in order to know the field size.
	digest->count = cpu_to_le32(digest_count);
	if (digest_count) {
		log_size += sizeof(*digest);
		log_size += log_digest_size;
	} else {
		log_size += sizeof(digest->count);
	}

	tail = log_base + log_size;
	tail->event_size = cpu_to_le32(event_size);
	memcpy(tail->event, event, event_size);
	log_size += sizeof(*tail) + event_size;

	return 0;
}

static struct {
	/*
	 * Event type. The event data is always UEFI_PLATFORM_FIRMWARE_BLOB2.
	 */
	u32 ev;
	/*
	 * Description added into the event. This is mostly useful for
	 * debugging. The verifier most likely finds images by hash.
	 */
	const char *desc;

} image_types[KVM_IMAGE_TYPE_MAX] = {
	[KVM_IMAGE_TYPE_KERNEL] = {
		.ev = TCG_EV_POST_CODE2,
		.desc = "KERNEL",
	},
	[KVM_IMAGE_TYPE_INITRD] = {
		.ev = TCG_EV_POST_CODE2,
		.desc = "INITRD",
	},
	[KVM_IMAGE_TYPE_FIRMWARE] = {
		.ev = TCG_EV_EFI_PLATFORM_FIRMWARE_BLOB2,
		.desc = "FIRMWARE",
	},
	[KVM_IMAGE_TYPE_DTB] = {
		.ev = TCG_EV_POST_CODE2,
		.desc = "DTB",
	},
	[KVM_IMAGE_TYPE_EVENT_LOG] = {
		.ev = TCG_EV_POST_CODE2,
		.desc = "LOG",
	},
};

int tpm_event_log_add_image(enum kvm_image_type image_type, const u8 *host_addr,
			    u64 base, size_t size)
{
	int ret;
	void *event;
	u32 event_type;
	const char *desc;
	size_t event_size;
	size_t desc_size = 0;
	struct uefi_platform_firmware_blob2_head *head;
	struct uefi_platform_firmware_blob2_tail *tail;

	pr_debug("Adding image %d (%p -> 0x%llx 0x%lx) to event log",
		 image_type, host_addr, base, size);

	if (image_type >= KVM_IMAGE_TYPE_MAX)
		return -EINVAL;

	desc = image_types[image_type].desc;
	event_type = image_types[image_type].ev;

	/* The EV_POST_CODE2 strings are *not* NUL-terminated */
	if (desc)
		desc_size = strlen(desc);

	event_size = sizeof(*head) + desc_size + sizeof(*tail);
	event = calloc(1, event_size);
	if (!event)
		return -ENOMEM;

	head = event;
	head->blob_description_size = desc_size;
	if (desc)
		memcpy(head->blob_description, desc, desc_size);

	tail = event + sizeof(*head) + desc_size;
	tail->blob_base = cpu_to_le64(base);
	tail->blob_size = cpu_to_le64(size);

	ret = tpm_event_log_add(event_type, event, event_size, host_addr, size);

	free(event);
	return ret;
}

size_t tpm_event_log_length(void)
{
	return log_size;
}

void tpm_event_log_close(void)
{
	EVP_MD_free(hash_func);
	EVP_MD_CTX_free(hash_context);
	hash_func = NULL;
	hash_context = NULL;
}
