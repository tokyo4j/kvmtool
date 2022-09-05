/*
 * Taken from perf which in turn take it from GIT
 */

#include "kvm/util.h"

#include <kvm/kvm.h>
#include <linux/magic.h>	/* For HUGETLBFS_MAGIC */
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>

static void report(const char *prefix, const char *err, va_list params)
{
	char msg[1024];
	vsnprintf(msg, sizeof(msg), err, params);
	fprintf(stderr, " %s%s\n", prefix, msg);
}

static NORETURN void die_builtin(const char *err, va_list params)
{
	report(" Fatal: ", err, params);
	exit(128);
}

static void error_builtin(const char *err, va_list params)
{
	report(" Error: ", err, params);
}

static void warn_builtin(const char *warn, va_list params)
{
	report(" Warning: ", warn, params);
}

static void info_builtin(const char *info, va_list params)
{
	report(" Info: ", info, params);
}

static void debug_builtin(const char *debug, va_list params)
{
	report(" Debug: ", debug, params);
}

void die(const char *err, ...)
{
	va_list params;

	va_start(params, err);
	die_builtin(err, params);
	va_end(params);
}

void pr_err(const char *err, ...)
{
	va_list params;

	if (loglevel < LOGLEVEL_ERROR)
		return;

	va_start(params, err);
	error_builtin(err, params);
	va_end(params);
}

void pr_warning(const char *warn, ...)
{
	va_list params;

	if (loglevel < LOGLEVEL_WARNING)
		return;

	va_start(params, warn);
	warn_builtin(warn, params);
	va_end(params);
}

void pr_info(const char *info, ...)
{
	va_list params;

	if (loglevel < LOGLEVEL_INFO)
		return;

	va_start(params, info);
	info_builtin(info, params);
	va_end(params);
}

/* Do not call directly; call pr_debug() instead. */
void __pr_debug(const char *debug, ...)
{
	va_list params;

	va_start(params, debug);
	debug_builtin(debug, params);
	va_end(params);
}

void die_perror(const char *s)
{
	perror(s);
	exit(1);
}

static u64 get_hugepage_blk_size(const char *hugetlbfs_path)
{
	struct statfs sfs;

	if (statfs(hugetlbfs_path, &sfs) < 0)
		die("Can't stat %s", hugetlbfs_path);

	if ((unsigned int)sfs.f_type != HUGETLBFS_MAGIC)
		die("%s is not hugetlbfs!", hugetlbfs_path);

	return sfs.f_bsize;
}

int memfd_alloc(u64 size, bool hugetlb, u64 blk_size)
{
	const char *name = "kvmtool";
	unsigned int flags = 0;
	int fd;

	if (hugetlb) {
		if (!is_power_of_two(blk_size))
			die("Hugepage size must be a power of 2");

		flags |= MFD_HUGETLB;
		flags |= blk_size << MFD_HUGE_SHIFT;
	}

	fd = memfd_create(name, flags);
	if (fd < 0)
		die_perror("Can't memfd_create for memory map");

	if (ftruncate(fd, size) < 0)
		die("Can't ftruncate for mem mapping size %lld",
			(unsigned long long)size);

	return fd;
}

/*
 * This function allocates memory aligned to align_sz.
 * It also wraps the decision between hugetlbfs (if requested) or normal mmap.
 */
void *mmap_anon_or_hugetlbfs_align(struct kvm *kvm, const char *hugetlbfs_path,
				   u64 size, u64 align_sz)
{
	u64 blk_size = 0;
	u64 total_map = size + align_sz;
	u64 start_off, end_off;
	void *addr_map, *addr_align;
	int fd;

	/*
	 * We don't /need/ to map guest RAM from hugetlbfs, but we do so
	 * if the user specifies a hugetlbfs path.
	 */
	if (hugetlbfs_path) {
		blk_size = get_hugepage_blk_size(hugetlbfs_path);

		if (blk_size == 0 || blk_size > size) {
			die("Can't use hugetlbfs pagesize %lld for mem size %lld",
				(unsigned long long)blk_size, (unsigned long long)size);
		}

		kvm->ram_pagesize = blk_size;
	} else {
		kvm->ram_pagesize = getpagesize();
	}

	/* Create a mapping with room for alignment without allocating. */
	addr_map = mmap(NULL, total_map, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0);
	if (addr_map == MAP_FAILED)
		return MAP_FAILED;

	fd = memfd_alloc(size, hugetlbfs_path, blk_size);
	if (fd < 0)
		return MAP_FAILED;

	/* Map the allocated memory in the fd to the specified alignment. */
	addr_align = (void *)ALIGN((u64)addr_map, align_sz);
	if (mmap(addr_align, size, PROT_RW, MAP_PRIVATE | MAP_FIXED, fd, 0) ==
	    MAP_FAILED) {
		close(fd);
		return MAP_FAILED;
	}

	/* Remove the mapping for unused address ranges. */
	start_off = addr_align - addr_map;
	if (start_off)
		munmap(addr_map, start_off);

	end_off = align_sz - start_off;
	if (end_off)
		munmap((void *)((u64)addr_align + size), end_off);

	kvm->ram_fd = fd;
	return addr_align;
}

void *mmap_anon_or_hugetlbfs(struct kvm *kvm, const char *hugetlbfs_path, u64 size)
{
	return mmap_anon_or_hugetlbfs_align(kvm, hugetlbfs_path, size, 0);
}
