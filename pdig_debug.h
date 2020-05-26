#ifndef PDIG_DEBUG_H
#define PDIG_DEBUG_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPECT(v) do { \
    int __ret = (v); \
	if(__ret < 0) { \
		fprintf(stderr, "%s failed at %s:%d with %d (errno %s)\n", #v, __FILE__, __LINE__, __ret, strerror(errno)); \
		abort(); \
	} \
} while(0)

#ifdef _DEBUG
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#define WARN(fmt, ...) fprintf(stderr, fmt " at %s:%d (errno %s)\n", __VA_ARGS__, __FILE__, __LINE__, strerror(errno))

#define cprintf(...) fprintf(stderr, __VA_ARGS__)

#ifdef _DEBUG
#define ASSERT(X) if(!(X)) { \
	fprintf(stderr, "%s:%d ASSERTION FAILED: "#X"\n", __FILE__, __LINE__); \
	abort(); \
}
#else
#define ASSERT(X)
#endif

#endif
