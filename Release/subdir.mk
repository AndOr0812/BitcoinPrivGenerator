################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../ListPrivateKey.c \
../args.c \
../bitcoin_module.c \
../combo.c \
../privkeys.c \
../pubkeys.c \
../shared_mem.c \
../tree.c 

OBJS += \
./ListPrivateKey.o \
./args.o \
./bitcoin_module.o \
./combo.o \
./privkeys.o \
./pubkeys.o \
./shared_mem.o \
./tree.o 

C_DEPS += \
./ListPrivateKey.d \
./args.d \
./bitcoin_module.d \
./combo.d \
./privkeys.d \
./pubkeys.d \
./shared_mem.d \
./tree.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -DUSE_ASM_X86_64=1 -DSTDC_HEADERS=1 -DUSE_ECMULT_STATIC_PRECOMPUTATION=1 -DUSE_FIELD_5x52=1 -DUSE_FIELD_INV_NUM=1 -DUSE_SCALAR_4x64=1 -I"/home/malego/Projects/workspace/bitcoin_finder" -I"/home/malego/Projects/workspace/bitcoin_finder/include" -I"/home/malego/Projects/workspace/bitcoin_finder/secp256k1_fast_unsafe" -I"/home/malego/Projects/workspace/bitcoin_finder/secp256k1_fast_unsafe/src" -O2 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


