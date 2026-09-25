RM := rm -rf
DHCPMON_TARGET := dhcpmon
CP := cp
MKDIR := mkdir
CC := g++
MV := mv
PWD := $(shell pwd)

# All of the sources participating in the build are defined here
-include src/subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: sonic-dhcpmon

# Tool invocations
sonic-dhcpmon: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: G++ C Linker'
	$(CC) -o "$(DHCPMON_TARGET)" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
install:
	$(MKDIR) -p $(DESTDIR)/usr/sbin
	$(MV) $(DHCPMON_TARGET) $(DESTDIR)/usr/sbin

deinstall:
	$(RM) $(DESTDIR)/usr/sbin/$(DHCPMON_TARGET)
	$(RM) -rf $(DESTDIR)/usr/sbin

# Unit tests. dh_auto_test runs the first of "check" or "test" that exists, so
# this is the entry point used during dpkg-buildpackage. It runs the plain suite
# only; the sanitized suite needs ASan/UBSan runtimes and is run separately in
# CI on amd64.
check:
	$(MAKE) -f test/Makefile test-plain

clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) $(DHCPMON_TARGET)
	-$(MAKE) -f test/Makefile clean
	-@echo ' '

.PHONY: all clean dependents check
