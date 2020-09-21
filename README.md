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

You can either build pdig statically or dynamically linked.
A dynamically linked pdig is more suitable for environments
where you can control the available libraries.
A statically linked pdig on the other hand is very useful if
pdig needs to be used in environments where you can't
make assumptions about the available libraries.

##### Dynamically linked
    git clone https://github.com/falcosecurity/pdig
    git clone https://github.com/draios/sysdig
    cd pdig
    mkdir -p build
    cd build
    cmake ..
    make
    # (optionally) sudo make install

##### Statically linked (using musl)

You can setup a musl toolchain yourself and then compile pdig
using the `-DMUSL_OPTIMIZED_BUILD=True` CMake flag.
However, a more convenient way is to do that using an alpine container.
An alpine container can be easily updated by downloading a new one
or doing `apk update`.

If you want to go the Alpine way:


```bash
mkdir source
cd source
git clone https://github.com/falcosecurity/pdig
git clone https://github.com/draios/sysdig
docker run -v $PWD:/source -it alpine:3.12 sh
```

Now in the container

```
apk add g++ gcc cmake cmake make libtool elfutils-dev libelf-static linux-headers
cd /source/pdig
mkdir -p build
cd build
cmake -DMUSL_OPTIMIZED_BUILD=True ..
make
```

You can now find the pdig binary in the source directory you created under `pdig/build/pdig`.

A quick `ldd` on that one shows this:

```
ldd build/pdig
  statically linked
```

If you don't want to go the Alpine way, you will need to grab a copy of [musl libc](https://www.musl-libc.org/),
compile it and then create a [musl gcc wrapper](https://www.musl-libc.org/how.html).
Once you have the wrapper you can compile pdig using the same instructions in this way:


```bash
git clone https://github.com/falcosecurity/pdig
git clone https://github.com/draios/sysdig
cd pdig
mkdir -p build
cd build
cmake -DMUSL_OPTIMIZED_BUILD=True ..
make
```
## How to run it?

Run `pdig` with the path (and arguments, if any) of the process you want to trace, similar to `strace(1)`, e.g.

    pdig [-a] curl https://example.com/

The `-a` option enables the full filter, which provides a richer set of instrumented system calls. You probably want to use this option with sysdig, but not with falco.

You can also attach to a running process with the `-p` option:

    pdig [-a] -p 1234

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

**Note**: When attaching to an already running process with `-p`, `pdig` will not use the seccomp filter by default.
You can force it with the `-S` option, but remember that a seccomp filter cannot be removed, so killing `pdig` will also kill the traced processes.
