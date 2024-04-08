obj-m += cwe_252.o
obj-m += cwe_467.o
obj-m += cwe_476.o
obj-m += cwe_676.o

all:
	make LLVM=1 ARCH=arm64 -C /home/cwe/linux M=$(PWD) modules

clean:
	make LLVM=1 ARCH=arm64 -C /home/cwe/linux M=$(PWD) clean
