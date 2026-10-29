# libxmp-lite-ps2-mopen-uaf
# libxmp-lite-ps2 mopen Use-After-Free (CWE-416)
Vulnerability: Heap Use-After-Free in `mopen()` / `mread()` of libxmp-lite-ps2 4.5.0
Affected repository: https://github.com/tatokis/libxmp-lite-ps2
Affected file: `src/memio.c`
CWE: CWE-416 Use After Free

## Summary
`mopen()` stores the raw pointer of an externally provided buffer without copying the buffer content or tracking its memory lifecycle. If the caller frees the source buffer while the `MFILE` handle remains valid, subsequent calls to `mread()` access the already-freed heap memory via `m->start`, resulting in heap-use-after-free. This can lead to denial of service or information disclosure.

## Reproduction
```bash
clang -fsanitize=address -g uaf_poc.c -o uaf_poc
./uaf_poc
```

Crash Evidence
```
=================================================================
==6192==ERROR: AddressSanitizer: heap-use-after-free on address 0x611000000040 at pc 0x560dba8d1477 bp 0x7fffa9ac0cd0 sp 0x7fffa9ac04a0
READ of size 16 at 0x611000000040 thread T0
    #0 0x560dba8d1476 in __asan_memcpy
    #1 0x560dba90d4c2 in mread /home/lloyd/Documents/libxmp-lite-ps2-master/uaf_poc.c:29:2
    #2 0x560dba90cfc4 in main /home/lloyd/Documents/libxmp-lite-ps2-master/uaf_poc.c:58:2
    #3 0x736d0cc29d8f in __libc_start_call_main
```
Full ASan log is preserved in this repository.

## Vulnerable Code Snippet
```c
MFILE *mopen(const void *ptr, long size)
{
	MFILE *m;
	m = (MFILE *)malloc(sizeof (MFILE));
	if (m == NULL)
		return NULL;
	
	m->start = ptr;
	m->pos = 0;
	m->size = size;
	return m;
}

int mclose(MFILE *m)
{
	free(m);
	return 0;
}

size_t mread(void *buf, size_t size, size_t num, MFILE *m)
{
 	size_t should_read = size * num;
 	ptrdiff_t can_read = CAN_READ(m);

 	if (!size || !num || can_read <= 0) {
 		return 0;
	}

	if (should_read > can_read) {
 		should_read = can_read;
	}

	memcpy(buf, m->start + m->pos, should_read);
 	m->pos += should_read;

	return should_read / size;
}
```
The flaw: `mopen()` only saves the raw external pointer `ptr` and does not copy buffer data. `mclose()` only frees the `MFILE` control structure, not the underlying user buffer. There is no runtime check whether `m->start` points to valid allocated memory.

## Patch
Two possible fixes:
1. Copy input buffer inside `mopen()`, and free the copied buffer inside `mclose()` (recommended, isolates lifetime).
2. Add documentation enforcing that the caller buffer must outlive the MFILE handle (not a runtime hardening).

Example patch sketch:
```c
MFILE *mopen(const void *ptr, long size)
{
	MFILE *m;
	m = (MFILE *)malloc(sizeof (MFILE));
	if (m == NULL)
		return NULL;
	void *buf_copy = malloc(size);
	if (!buf_copy) {
		free(m);
		return NULL;
	}
	memcpy(buf_copy, ptr, size);
	m->start = buf_copy;
	m->pos = 0;
	m->size = size;
	return m;
}

int mclose(MFILE *m)
{
	if (m) {
		free((void*)m->start);
		free(m);
	}
	return 0;
}
```

## Credits
Lidi Jie, School of Cyber Science and Engineering, Wuhan University
```
