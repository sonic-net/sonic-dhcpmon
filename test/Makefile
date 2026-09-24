# Unit tests for the dhcpmon option parsers.
#
# Run from the repository root:
#     make -f test/Makefile test          # sanitized build (ASan + UBSan)
#     make -f test/Makefile test-plain    # optimized build, no sanitizers
#     make -f test/Makefile clean

CXX := g++
CXXFLAGS := -std=c++17 -g3 -Wall -Wextra -I/usr/include/swss -fmessage-length=0
# Alignment checking is disabled deliberately: dhcpmon parses raw captured
# frames in place, so the IP header always sits at Ethernet offset 14 and can
# never be 4 byte aligned. That is a pre-existing property of the daemon and is
# unrelated to the option bounds checks these tests cover.
SANFLAGS := -O1 -fsanitize=address,undefined -fno-sanitize=alignment -fno-omit-frame-pointer
TESTDIR := test
BUILDDIR := $(TESTDIR)/build

SRCS := $(TESTDIR)/test_packet_handler_options.cpp

.PHONY: test test-plain clean

# Sanitized run: any read past an option buffer aborts the test binary.
test: $(BUILDDIR)/test_options_san
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 $<

test-plain: $(BUILDDIR)/test_options
	$<

$(BUILDDIR)/test_options_san: $(SRCS) | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(SANFLAGS) -o $@ $(SRCS)

$(BUILDDIR)/test_options: $(SRCS) | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -O2 -o $@ $(SRCS)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR)
