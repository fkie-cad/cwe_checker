FROM ubuntu:noble as builder

# This container is used to build the sample kernel modules.

# Kernel release to build the modules against. When changing the minor or
# major release make sure to update the curl command below.
ARG LX_VER="6.7.6"

# Install tools required to build a kernel.
RUN set -x && \
    echo 'debconf debconf/frontend select Noninteractive' | \
    debconf-set-selections && \
    apt-get update && \
    apt-get install -y -q apt-utils dialog && \
    apt-get install -y -q \
	bc \
	bison \
	bsdmainutils \
	clang \
	clang-tools \
	curl \
	flex \
	git \
	libelf-dev \
	libncurses5-dev \
	libssl-dev \
	lld \
	llvm \
	make \
	sparse \
        sudo && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

RUN set -x && \
    useradd -m cwe && \
    echo "cwe:cwe" | \
    chpasswd && \
    adduser cwe sudo && \
    sed -i.bkp -e 's/%sudo\s\+ALL=(ALL\(:ALL\)\?)\s\+ALL/%sudo ALL=NOPASSWD:ALL/g' /etc/sudoers

USER cwe

# Download the kernel.
WORKDIR /home/cwe
RUN set -x && \
    curl https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${LX_VER}.tar.gz -o linux.tar.gz && \
    tar xf linux.tar.gz && \
    mv linux-${LX_VER} linux

# Build a minimal kernel with support for external modules.
WORKDIR /home/cwe/linux
ENV ARCH=arm64
ENV LLVM=1
COPY modules.config.fragment .
COPY debug.config.fragment .
RUN set -x && \
    make allnoconfig && \
    ./scripts/kconfig/merge_config.sh -n -m .config debug.config.fragment modules.config.fragment && \
    make -j$(nproc) Image modules modules_prepare

# Build our sample modules.
WORKDIR /home/cwe/build
COPY *.c .
COPY Makefile .
ENV KBUILD_VERBOSE=1
RUN set -x && \
    mkdir build && \
    make all && \
    for m in $(find . -name '*.ko'); do cp $m "build/${m%.*}_aarch64_clang.ko"; done

# Copy into a new Docker image to save space.
FROM scratch
COPY --from=builder /home/cwe/build/build /build
