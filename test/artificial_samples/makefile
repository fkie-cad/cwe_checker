CC_x64=gcc
CC_X86=gcc
CC_ARM=arm-linux-gnueabi-gcc
CC_MIPS=mips-linux-gnu-gcc
CC_PPC=powerpc-linux-gnu-gcc

CPP_x64=g++
CPP_X86=g++
CPP_ARM=arm-linux-gnueabi-g++-5
CPP_MIPS=mips-linux-gnu-g++-5
CPP_PPC=powerpc-linux-gnu-g++-5

CFLAGS_X64=-O0 -g -fno-stack-protector -std=c11
CFLAGS_X86=-O0 -g -m32 -fno-stack-protector -std=c11
CFLAGS_ARM=-O0 -g -fno-stack-protector -std=c11
CFLAGS_MIPS=-O0 -g -fno-stack-protector -std=c11
CFLAGS_PPC=-O0 -g -fno-stack-protector -std=c11

CPPFLAGS_X64=-O0 -g -fno-stack-protector
CPPFLAGS_X86=-O0 -g -m32 -fno-stack-protector
CPPFLAGS_ARM=-O0 -g -fno-stack-protector
CPPFLAGS_MIPS=-O0 -g -fno-stack-protector
CPPFLAGS_PPC=-O0 -g -fno-stack-protector

define compile_x64
	@echo "Compiling x64 target:" $(1)
	$(CC_x64) $(CFLAGS_X64) -o build/$(1)_x64.out $(1).c
	execstack -s build/$(1)_x64.out
endef

define compile_x64_cpp
	@echo "Compiling x64 target:" $(1)
	$(CPP_x64) $(CPPFLAGS_X64) -o build/$(1)_x64.out $(1).cpp
	execstack -s build/$(1)_x64.out
endef

define compile_x86
	@echo "Compiling x86 target:" $(1)
	$(CC_X86) $(CFLAGS_X86) -o build/$(1)_x86.out $(1).c
	execstack -s build/$(1)_x86.out
endef

define compile_x86_cpp
	@echo "Compiling x86 target:" $(1)
	$(CPP_X86) $(CPPFLAGS_X86) -o build/$(1)_x86.out $(1).cpp
	execstack -s build/$(1)_x86.out
endef

define compile_mips
	@echo "Compiling mips target:" $(1)
	$(CC_MIPS) $(CFLAGS_MIPS) -o build/$(1)_mips.out $(1).c
	execstack -s build/$(1)_mips.out
endef

define compile_mips_cpp
	@echo "Compiling mips target:" $(1)
	$(CPP_MIPS) $(CPPFLAGS_MIPS) -o build/$(1)_mips.out $(1).cpp
	execstack -s build/$(1)_mips.out
endef

define compile_arm
	@echo "Compiling arm target:" $(1)
	$(CC_ARM) $(CFLAGS_ARM) -o build/$(1)_arm.out $(1).c
	execstack -s build/$(1)_arm.out
endef

define compile_arm_cpp
	@echo "Compiling arm target:" $(1)
	$(CPP_ARM) $(CPPFLAGS_ARM) -o build/$(1)_arm.out $(1).cpp
	execstack -s build/$(1)_arm.out
endef

define compile_ppc
	@echo "Compiling ppc target:" $(1)
	$(CC_PPC) $(CFLAGS_PPC) -o build/$(1)_ppc.out $(1).c
	execstack -s build/$(1)_ppc.out
endef

define compile_ppc_cpp
	@echo "Compiling ppc target:" $(1)
	$(CPP_PPC) $(CPPFLAGS_PPC) -o build/$(1)_ppc.out $(1).cpp
	execstack -s build/$(1)_ppc.out
endef

define compile_all
	$(shell mkdir -p "build")
	$(call compile_x64,$(1))
	$(call compile_x86,$(1))
	$(call compile_arm,$(1))
	$(call compile_mips,$(1))
	$(call compile_ppc,$(1))
endef

define compile_all_cpp
	$(shell mkdir -p "build")
	$(call compile_x64_cpp,$(1))
	$(call compile_x86_cpp,$(1))
	$(call compile_arm_cpp,$(1))
	$(call compile_mips_cpp,$(1))
	$(call compile_ppc_cpp,$(1))
endef

all:
	$(call compile_all,c_constructs)
	$(call compile_all,cwe_190)
	$(call compile_all,cwe_243)
	$(call compile_all,cwe_243_clean)
	$(call compile_all_cpp,cwe_248)
	$(call compile_all,cwe_332)
	$(call compile_all,cwe_367)
	$(call compile_all,cwe_415)
	$(call compile_all,cwe_426)
	$(call compile_all,cwe_457)
	$(call compile_all,cwe_467)
	$(call compile_all,cwe_476)
	$(call compile_all,cwe_478)
	$(call compile_all,cwe_676)
	$(call compile_x64,cwe_782)
	$(call compile_all,arrays)
	$(call compile_all,memory_access)

clean:
	rm -rf build
