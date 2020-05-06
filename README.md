# pdig

A standalone executable based on ptrace and sysdig libraries.

## Why pdig?

In some environments, like managed Kubernetes clusters, you cannot install your own kernel modules or eBPF probes.
This means you cannot use the high-performance in-kernel tracing, but with pdig you can still instrument your applications using ptrace.

## How to build it?

#### Prerequisites:

1. An x86-64 machine, as it's the only supported architecture now
2. `cmake` and the standard C/C++ toolchain (notably `gcc` and `g++`)

#### Instructions

    git clone https://github.com/ografa/pdig
    git clone https://github.com/draios/sysdig
    cd pdig
    mkdir -p build
    cd build
    cmake ..
    make
    # (optionally) sudo make install

## How to run it?

Run `pdig` with the path (and arguments, if any) of the process you want to trace, similar to `strace(1)`, e.g.

    pdig curl https://example.com/

To observe any effect, you will need e.g. falco or sysdig running in a separate process, with udig (userspace instrumentation) enabled. For example:

    sysdig -u

## How slow is this?

Better than strace at least. While we can't do much about ptrace overhead, we use [seccomp filters](http://man7.org/linux/man-pages/man2/seccomp.2.html)
to limit the kinds of system calls we instrument.

With the caveat that there are lies, damn lies and benchmarks, here are some results from OSBench, as compared to a run without instrumentation:

	| Test    | Configuration      | Relative |
	| ------- | ------------------ | -------- |
	| osbench | Create Files       | 0.245    |
	| osbench | Create Threads     | 0.495    |
	| osbench | Launch Programs    | 0.255    |
	| osbench | Create Processes   | 0.285    |
	| osbench | Memory Allocations | 1.005    |

i.e. the worst case for OSBench is roughly 1/4 the original performance for system call heavy workloads.

