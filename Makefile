RM := rm -rf
DHCPMON_TARGET := dhcpmon
HEALTH_TEST_TARGET := tests/health_accounting_test
CP := cp
MKDIR := mkdir
CC := g++
MV := mv
PWD := $(shell pwd)

# All of the sources participating in the build are defined here
-include src/subdir.mk
-include objects.mk

HEALTH_TEST_OBJS := $(filter-out ./src/main.o ./src/dhcp_mon.o,$(OBJS))

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

$(HEALTH_TEST_TARGET): tests/health_accounting_test.cpp $(HEALTH_TEST_OBJS) $(wildcard src/*.h)
	$(CC) -O3 -g3 -Wall -I/usr/include/swss -Isrc -o "$@" "$<" $(HEALTH_TEST_OBJS) $(LIBS)

test-health: $(HEALTH_TEST_TARGET)
	./$(HEALTH_TEST_TARGET)

# Other Targets
install:
	$(MKDIR) -p $(DESTDIR)/usr/sbin
	$(MV) $(DHCPMON_TARGET) $(DESTDIR)/usr/sbin

deinstall:
	$(RM) $(DESTDIR)/usr/sbin/$(DHCPMON_TARGET)
	$(RM) -rf $(DESTDIR)/usr/sbin

clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) $(DHCPMON_TARGET) $(HEALTH_TEST_TARGET)
	-@echo ' '

.PHONY: all clean dependents test-health
