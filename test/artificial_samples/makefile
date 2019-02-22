CC_x64=gcc
CC_X86=./dockcross-linux-x86 gcc
CC_ARM=arm-linux-gnueabi-gcc
CC_MIPS=mips-linux-gnu-gcc
CC_PPC=powerpc-linux-gnu-gcc

CPP_x64=g++
CPP_X86=./dockcross-linux-x86 g++
CPP_ARM=arm-linux-gnueabi-g++-5
CPP_MIPS=mips-linux-gnu-g++-5
CPP_PPC=powerpc-linux-gnu-g++-5

CFLAGS_X64=-g -fno-stack-protector -std=c11
CFLAGS_X86=-g -m32 -fno-stack-protector -std=c11
CFLAGS_ARM=-g -fno-stack-protector -std=c11
CFLAGS_MIPS=-g -fno-stack-protector -std=c11
CFLAGS_PPC=-g -fno-stack-protector -std=c11

CPPFLAGS_X64=-g -fno-stack-protector
CPPFLAGS_X86=-g -m32 -fno-stack-protector
CPPFLAGS_ARM=-g -fno-stack-protector
CPPFLAGS_MIPS=-g -fno-stack-protector
CPPFLAGS_PPC=-g -fno-stack-protector

OPTIMIZE=-O3
NO_OPTIMIZE=-O0

define compile_x64
	@echo "Compiling x64 target:" $(1)
	$(CC_x64) $(CFLAGS_X64) $(2) -o build/$(1)_x64.out $(1).c
	 execstack -s build/$(1)_x64.out
endef

define compile_x64_cpp
	@echo "Compiling x64 target:" $(1)
	$(CPP_x64) $(CPPFLAGS_X64) $(2) -o build/$(1)_x64.out $(1).cpp
	execstack -s build/$(1)_x64.out
endef

define compile_x86
	@echo "Compiling x86 target:" $(1)
	$(CC_X86) $(CFLAGS_X86) $(2) -o build/$(1)_x86.out $(1).c
	execstack -s build/$(1)_x86.out
endef

define compile_x86_cpp
	@echo "Compiling x86 target:" $(1)
	$(CPP_X86) $(CPPFLAGS_X86) $(2) -o build/$(1)_x86.out $(1).cpp
	execstack -s build/$(1)_x86.out
endef

define compile_mips
	@echo "Compiling mips target:" $(1)
	$(CC_MIPS) $(CFLAGS_MIPS) $(2) -o build/$(1)_mips.out $(1).c
	execstack -s build/$(1)_mips.out
endef

define compile_mips_cpp
	@echo "Compiling mips target:" $(1)
	$(CPP_MIPS) $(CPPFLAGS_MIPS) $(2) -o build/$(1)_mips.out $(1).cpp
	execstack -s build/$(1)_mips.out
endef

define compile_arm
	@echo "Compiling arm target:" $(1)
	$(CC_ARM) $(CFLAGS_ARM) $(2) -o build/$(1)_arm.out $(1).c
	execstack -s build/$(1)_arm.out
endef

define compile_arm_cpp
	@echo "Compiling arm target:" $(1)
	$(CPP_ARM) $(CPPFLAGS_ARM) $(2) -o build/$(1)_arm.out $(1).cpp
	execstack -s build/$(1)_arm.out
endef

define compile_ppc
	@echo "Compiling ppc target:" $(1)
	$(CC_PPC) $(CFLAGS_PPC) $(2) -o build/$(1)_ppc.out $(1).c
	execstack -s build/$(1)_ppc.out
endef

define compile_ppc_cpp
	@echo "Compiling ppc target:" $(1)
	$(CPP_PPC) $(CPPFLAGS_PPC) $(2) -o build/$(1)_ppc.out $(1).cpp
	execstack -s build/$(1)_ppc.out
endef

define compile_all
	$(shell mkdir -p "build")
	$(call compile_x64,$(1),$(2))
	$(call compile_x86,$(1),$(2))
	$(call compile_arm,$(1),$(2))
	$(call compile_mips,$(1),$(2))
	$(call compile_ppc,$(1),$(2))
endef

define compile_all_cpp
	$(shell mkdir -p "build")
	$(call compile_x64_cpp,$(1),$(2))
	$(call compile_x86_cpp,$(1),$(2))
	$(call compile_arm_cpp,$(1),$(2))
	$(call compile_mips_cpp,$(1),$(2))
	$(call compile_ppc_cpp,$(1),$(2))
endef

all:
	$(call compile_all,c_constructs,$(NO_OPTIMIZE))
	$(call compile_all,cwe_190,$(NO_OPTIMIZE))
	$(call compile_all,cwe_243,$(NO_OPTIMIZE))
	$(call compile_all,cwe_243_clean,$(NO_OPTIMIZE))
	$(call compile_all_cpp,cwe_248,$(NO_OPTIMIZE))
	$(call compile_all,cwe_332,$(NO_OPTIMIZE))
	$(call compile_all,cwe_367,$(NO_OPTIMIZE))
	$(call compile_all,cwe_415,$(NO_OPTIMIZE))
	$(call compile_all,cwe_426,$(NO_OPTIMIZE))
	$(call compile_all,cwe_457,$(NO_OPTIMIZE))
	$(call compile_all,cwe_467,$(NO_OPTIMIZE))
	$(call compile_all,cwe_476,$(OPTIMIZE))
	$(call compile_all,cwe_478,$(NO_OPTIMIZE))
	$(call compile_all,cwe_676,$(NO_OPTIMIZE))
	$(call compile_x64,cwe_782,$(NO_OPTIMIZE))
	$(call compile_all,arrays,$(NO_OPTIMIZE))
	$(call compile_all,memory_access,$(NO_OPTIMIZE))

clean:
	rm -rf build
