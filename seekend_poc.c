#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>

typedef ptrdiff_t mpos_t;

typedef struct {
	const uint8_t *start;
	mpos_t pos;
	mpos_t size;
} MFILE;

static inline ptrdiff_t CAN_READ(MFILE *m)
{
	if (m->size >= 0)
		return m->pos >= 0 ? m->size - m->pos : 0;
	return INT_MAX;
}

static int mseek(MFILE *m, long offset, int whence)
{
	switch (whence) {
	default:
	case SEEK_SET:
		if (m->size >= 0 && (offset > m->size || offset < 0))
			return -1;
		m->pos = offset;
		return 0;
	case SEEK_CUR:
		if (m->size >= 0 && (offset > CAN_READ(m) || offset < -m->pos))
			return -1;
		m->pos += offset;
		return 0;
	case SEEK_END:
		if (m->size < 0)
			return -1;
		m->pos = m->size + offset;   // Vulnerability: missing bounds validation
		return 0;
	}
}

static long mtell(MFILE *m)
{
	return (long)m->pos;
}

static MFILE *mopen(const void *ptr, long size)
{
	MFILE *m = malloc(sizeof(MFILE));
	if (!m)
		return NULL;
	m->start = ptr;
	m->pos = 0;
	m->size = size;
	return m;
}

static int mclose(MFILE *m)
{
	free(m);
	return 0;
}

int main(void)
{
	/* Stack buffer; ASan places redzones around stack objects */
	uint8_t buf[256];
	memset(buf, 0, sizeof(buf));

	MFILE *mf = mopen(buf, 256);

	/* SEEK_END with offset=1 sets pos = 257, out of the valid buffer range */
	mseek(mf, 1, SEEK_END);
	fprintf(stderr, "pos = %ld, buffer size = 256\n", mtell(mf));

	/* Simulate unsafe manual pointer access pattern seen in real loader code:
	 * retrieve position via mtell() and index directly, bypassing CAN_READ() checks.
	 * This triggers out-of-bounds read using the invalid position stored by mseek().
	 */
	volatile uint8_t dummy = mf->start[mf->pos];
	(void)dummy;

	mclose(mf);
	return 0;
}

