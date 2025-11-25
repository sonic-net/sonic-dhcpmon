# Add inputs and outputs from these tool invocations to the build variables 
CC := g++

C_SRCS += \
../src/dhcp_check_profile_relay.cpp \
../src/health_check.cpp \
../src/packet_handler.cpp \
../src/sock_mgr.cpp \
../src/event_mgr.cpp \
../src/dhcp_device.cpp \
../src/dhcp_devman.cpp \
../src/dhcp_mon.cpp \
../src/util.cpp \
../src/main.cpp 

OBJS += \
./src/dhcp_check_profile_relay.o \
./src/health_check.o \
./src/packet_handler.o \
./src/sock_mgr.o \
./src/event_mgr.o \
./src/dhcp_device.o \
./src/dhcp_devman.o \
./src/dhcp_mon.o \
./src/util.o \
./src/main.o 

C_DEPS += \
./src/dhcp_check_profile_relay.d \
./src/health_check.d \
./src/packet_handler.d \
./src/sock_mgr.d \
./src/event_mgr.d \
./src/dhcp_device.d \
./src/dhcp_devman.d \
./src/dhcp_mon.d \
./src/util.d \
./src/main.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: src/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) -O3 -g3 -Wall -I/usr/include/swss -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
