#ifndef PDIG_SECCOMP_H
#define PDIG_SECCOMP_H

#ifdef __cplusplus
extern "C" {
#endif

struct sock_fprog;

struct sock_fprog* build_filter(bool capture_all);

#ifdef __cplusplus
}
#endif

#endif
