#include "config.h"


void
perror_pid(const char *msg, pid_t pid) {
	char outbuf[1024];

	memset(outbuf, 0, sizeof(outbuf));
	snprintf(outbuf, sizeof(outbuf), "%sError in %s (%d)%s",
		BOLDRED, msg, pid, RESET);
	perror(outbuf);
	return;
}

pid_t
gettid(void) {
	return (pid_t)(syscall(SYS_gettid));
}


typedef struct vmap_region {
	unsigned long start;
	unsigned long end;
} vmap_region_t;

#define MAX_VMA	128

void *
map_closest_area(void *refaddr, size_t msize) {
	FILE *f;
	void *result;
	vmap_region_t vmaps[MAX_VMA];
	unsigned long uaddr = (unsigned long)refaddr;
	size_t i, cind = 0, closest = ~(0), vind = 0;

	if ((f = fopen("/proc/self/maps", "r")) == NULL) {
		perror_pid("fopen(/proc/self/maps", 0);
		return NULL;
	}

	memset(vmaps, 0, sizeof(vmaps));

	while (!feof(f) && (vind < sizeof(vmaps)/sizeof(vmaps[0])-1)) {
		char mline[512], *sp, *hyph;
		int err = 0;

		memset(mline, 0, sizeof(mline));

		if (!fgets(mline, sizeof(mline), f))
			break;
		else if (!mline[0])
			continue;

		mline[strlen(mline)-1] = 0;

		sp = strchr(mline, ' ');
		hyph = strchr(mline, '-');

		if (!sp || !hyph || (sp < hyph))
			continue;

		*sp = 0;
		*hyph++ = 0;

		errno = 0;
		vmaps[vind].start = strtoul(mline, NULL, 16);

		if (errno)
			err = 1;
		else {
			errno = 0;
			vmaps[vind].end = strtoul(hyph, NULL, 16);

			if (errno)
				err = 1;
		}

		if (err)
			continue;

		vind++;
	}

	// We made sure in the loop above we hold onto an extra VMA slot at the end
	if (vind) {
		vmaps[vind].start = (vmaps[vind-1].end + 8192) & ~(0xfff);
		vmaps[vind].end = ~0;
	}

	for (i = 0; i < vind; i++) {
		if ((uaddr < vmaps[i].start) && (vmaps[i].start - uaddr < closest)) {
			cind = i;
			closest = vmaps[i].start - uaddr;
		} else if ((uaddr > vmaps[i].end) && (uaddr - vmaps[i].end < closest)) {
			cind = i;
			closest = uaddr - vmaps[i].end;
		}

//		fprintf(stderr, "VMAP[%zu]: %lx -> %lx\n", i, vmaps[i].start, vmaps[i].end);
	}

//	fprintf(stderr, "VMAP[END]: %lx -> %lx\n", vmaps[vind].start, vmaps[vind].end);
	fprintf(stderr, "VMAP:CLOSEST[%zu]: %lx -> %lx\n", cind, vmaps[cind].start, vmaps[cind].end);

	for (i = cind; i < vind+1; i++) {

		if ((vmaps[i+1].start - vmaps[i].end) >= msize) {
			void *base = (void *)vmaps[i+1].end;

			if ((result = mmap(base, msize, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, 0, 0)) == MAP_FAILED) {
				char merrbuf[128];

				snprintf(merrbuf, sizeof(merrbuf), "mmap(%p, ...)", base);
				perror_pid(merrbuf, 0);
				return NULL;
			}

			fprintf(stderr, "------- base: %p\n", base);
			return result;
		}

	}

	return NULL;
}

size_t
make_jmp_buf(unsigned long from, unsigned long to, void *buf, size_t buflen) {
	unsigned char *iptr = (unsigned char *)buf;
	uint32_t imm;
	ssize_t offset = to - from;

	if (buflen < 5)
		return 0;

	if (offset > 0)
		offset -= 5;
	else
		offset -= 5;

	if ((offset > 0x7fffffff) || (offset < -0x7fffffff))
		return 0;

	imm = offset;

	*iptr++ = 0xe9;
	memcpy(iptr, &imm, sizeof(imm));

	return 5;
}
