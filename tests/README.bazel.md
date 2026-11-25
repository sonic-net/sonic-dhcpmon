# Production utility behavior test

`//:util_behavior_test` compiles the actual `src/util.cpp` and uses source Common,
jsoncpp and pinned external foundations. Only the daemon uses libpcap. Assertions remain on
in optimized builds (`-UNDEBUG`). Ten groups cover checksum lengths0..65, carry
folds, IPv4/IPv6 pseudoheaders and zero encoding, parsing boundaries, address
formatting, counter keys and legacy serialization. Empty application-state globals
allow pure utility paths to run; no DB methods are mocked or called. This is not
full packet forwarding, database health or dual-ToR acceptance.

The published infrastructure native_runtime_test wrapper uses declared target
loader/library payloads, not an absolute host path or locally built image.
The PR workflow runs this target without cached test results on native AMD64
and ARM64 Debian Trixie. See each architecture's test log for the result on
the current commit. Neither check exercises a cross-architecture runtime.
