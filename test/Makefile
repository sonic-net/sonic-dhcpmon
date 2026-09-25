# Unit tests for the dhcpmon option parsers.
#
# Run from the repository root:
#     make -f test/Makefile test          # sanitized build (ASan + UBSan)
#     make -f test/Makefile test-plain    # optimized build, no sanitizers
#     make -f test/Makefile clean
#
# "make check" in the top level Makefile runs the plain suite; that is the
# target dh_auto_test invokes during dpkg-buildpackage.

CXX ?= g++

# Flags the suite requires in order to compile at all. Any CXXFLAGS supplied by
# the caller (dpkg-buildpackage exports hardening flags, for example) are
# appended rather than substituted, so a package build cannot drop the include
# path or the language standard.
TEST_CXXFLAGS := -std=c++17 -g3 -Wall -Wextra -I. -I/usr/include/swss -fmessage-length=0 $(CXXFLAGS)

# Alignment checking is disabled deliberately: dhcpmon parses raw captured
# frames in place, so the IP header always sits at Ethernet offset 14 and can
# never be 4 byte aligned. That is a pre-existing property of the daemon and is
# unrelated to the option bounds checks these tests cover.
SANFLAGS := -O1 -fsanitize=address,undefined -fno-sanitize=alignment -fno-omit-frame-pointer
TESTDIR := test
BUILDDIR := $(TESTDIR)/build

SRCS := $(TESTDIR)/test_packet_handler_options.cpp

BINARIES := $(BUILDDIR)/test_options_san $(BUILDDIR)/test_options
DEPS := $(BINARIES:=.d)

# The test source #includes src/packet_handler.cpp to reach its file static
# parsers, so the real prerequisites are the production sources and every header
# they pull in. Letting the compiler generate them keeps that list correct
# automatically; without this, editing the parser and rerunning the documented
# command silently executes the previously built binary.
# -MT names the rule after the executable, which is required here because the
# default target would otherwise be derived from the input source name.
DEPFLAGS = -MMD -MP -MF $@.d -MT $@

.PHONY: test test-plain clean

# Sanitized run: any read past an option buffer aborts the test binary.
test: $(BUILDDIR)/test_options_san
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 $<

test-plain: $(BUILDDIR)/test_options
	$<

$(BUILDDIR)/test_options_san: $(SRCS) | $(BUILDDIR)
	$(CXX) $(TEST_CXXFLAGS) $(SANFLAGS) $(DEPFLAGS) -o $@ $(SRCS)

$(BUILDDIR)/test_options: $(SRCS) | $(BUILDDIR)
	$(CXX) $(TEST_CXXFLAGS) -O2 $(DEPFLAGS) -o $@ $(SRCS)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR)

-include $(DEPS)
