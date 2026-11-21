# Linux Architectures

## Official fork releases (temporary independent distribution)

The `ach1992/EZTunnel` one-line installer downloads the fork's official
`eztunnel-linux-x86_64.tar.gz` or `eztunnel-linux-aarch64.tar.gz`.
These **full-featured GNU/Linux builds are dynamically linked**, produced
natively on Ubuntu 24.04 x86-64 and ARM64 GitHub runners. They are **not**
the optional static musl binaries documented below.

The compatibility baseline for these artifacts is **glibc 2.39 and the
standard shared runtime libraries available on Ubuntu 24.04**, on the
corresponding architecture. Ubuntu 24.04 and newer and Debian 13 are the
intended system families for this fork; use actual ELF requirements, not
a hard-coded OS-name prohibition, for other distributions. The build job
records ELF machine, interpreter, shared libraries and required GLIBC
symbol versions in the `elf-abi.txt` artifact, checks the ABI against
Ubuntu 24.04 and runs `eztunnel --version` before publishing. A program
that cannot start on a target host is rejected by the installer **before**
it replaces an installed executable. Real cross-distribution and
two-architecture installation still require post-Release acceptance.

An x86-64 host selects `x86_64`/`amd64`; ARM64 selects
`aarch64`/`arm64`. Both include browser-compatible TLS and all default
features. The installer checks ELF architecture and SHA256SUMS.

## Optional static musl builds

The repository also provides separate build scripts for optional static
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` builds.
They are not used by the fork's GitHub Release workflow. Prior static
build reports for upstream versions (x86-64 static PIE, ARM64 ET_EXEC)
describe that separate toolchain, not the present fork Release artifacts.

## Ordinary Builds

`cargo build --locked --release` builds for the installed native Rust toolchain.
For static Linux use `scripts/build-x86_64-musl.sh` or
`scripts/build-aarch64-cross.sh`; both call `scripts/build-static.sh` with one
consistent musl C/C++ toolchain. Install the matching Rust musl target first.
Native/cross musl C, C++ and assembly compilers, CMake and libclang are needed for
the full default browser-TLS build. Do not use host glibc headers for ARM musl
bindgen or accidentally link host C++ libraries.

## Optional ARM64 musl cross-toolchain

The earlier static-musl validation used Rust 1.98.1, its official ARM64 musl
standard library, Zig0.17.1 C/C++/libc++ sysroot, and LLVM22.1.8 final linker and
libclang. `scripts/build-aarch64-cross.sh` and `scripts/cross/` record the necessary
target, header and CMake configuration. Provision tools separately; build scripts
do not download/install software or execute upstream installer scripts.

```sh
export EZTUNNEL_ZIG=/absolute/zig-x86_64-linux-0.17.1/zig
export EZTUNNEL_CLANGXX=/absolute/llvm-22/bin/clang++
export LIBCLANG_PATH=/absolute/llvm-22/lib
# Ensure the matching ld.lld is on PATH and Rust ARM64 musl std is installed.
bash scripts/build-aarch64-cross.sh
bash scripts/package-linux.sh target/aarch64-unknown-linux-musl/release/eztunnel dist-arm64
```

Use a dedicated Zig cache for this target. C/C++ code uses Zig's musl headers and
static libc++/libc++abi; the final Rust link uses LLVM lld so the required
`--fix-cortex-a53-843419` workaround remains enabled. No erratum or security flag
was removed to make the build pass. The package script reads the binary's ELF
machine instead of naming it after the build host, and never executes a foreign
binary while packaging. Runtime license notices are added to each release archive.

## Historical static-build validation (not current fork Release QA)

Historical upstream static builds passed the same 490-test browser-enabled inventory natively.
ARM64 validation used private namespaces on an ARM64 host, not QEMU. Kernel/raw/
TUN/Mirage, browser TLS, direct datagrams, migration, hopping, packet fallback,
CLI/PTY, wrong-architecture installation and lifecycle tests are included.
The release report distinguishes direct-WAN mixed-architecture checks from opaque
SSH loopback relays used where inbound test ports were unreachable. No firewall
or production installation was changed to make tests pass.

ARM and x86 performance measurements use different hosts and cannot isolate CPU
architecture as the cause of speed differences. See the versioned validation
report for exact workloads, binaries, toolchain hashes and limitations.

The known0.9.1 gaming-option risks remain: opt-in adaptive control can develop
long-run queueing, direct-channel renewal/rebinding can lose UDP, and TCP packet
fallback can have high tail latency. ARM support does not claim to fix those
algorithm/network risks. Ordinary defaults remain unchanged.
