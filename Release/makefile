################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include secp256k1_fast_unsafe/src/.libs/subdir.mk
-include secp256k1_fast_unsafe/src/subdir.mk
-include secp256k1_fast_unsafe/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: bitcoin_finder

# Tool invocations
bitcoin_finder: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	gcc -L"/home/malego/Projects/workspace/bitcoin_finder/libs" -o "bitcoin_finder" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) bitcoin_finder
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
