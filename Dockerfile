# based on https://github.com/BinaryAnalysisPlatform/bap/blob/master/docker/Dockerfile
FROM phusion/baseimage:0.11
RUN apt-get -y update && apt-get -y install \
    build-essential \
    curl \
    git \
    libx11-dev \
    m4 \
    pkg-config \
    python-pip \
    software-properties-common \
    sudo \
    unzip \
    wget \
	binutils-multiarch \
	clang \
	libgmp-dev \
	libzip-dev \
	llvm-6.0-dev \
	zlib1g-dev \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*
RUN wget https://raw.githubusercontent.com/ocaml/opam/master/shell/install.sh
RUN yes /usr/local/bin | sh install.sh
RUN useradd -m bap && echo "bap:bap" | chpasswd && adduser bap sudo
RUN sed -i.bkp -e \
      's/%sudo\s\+ALL=(ALL\(:ALL\)\?)\s\+ALL/%sudo ALL=NOPASSWD:ALL/g' \
      /etc/sudoers
USER bap
WORKDIR /home/bap
# install Bap
RUN opam init --auto-setup --comp=4.05.0 --disable-sandboxing --yes
RUN git clone -b testing --single-branch https://github.com/BinaryAnalysisPlatform/opam-repository.git
RUN opam repo add bap opam-repository
RUN opam update
RUN opam install depext --yes
RUN OPAMJOBS=1 opam depext --install bap --yes
RUN pip install bap
# install CWE_Checker and dependencies
RUN OPAMJOBS=1 opam install yojson alcotest --yes
COPY . /home/bap/cwe_checker/
RUN sudo chown -R bap:bap /home/bap/cwe_checker
ENV PATH="/home/bap/.opam/4.05.0/bin/:${PATH}"
WORKDIR /home/bap/cwe_checker/src
RUN bapbuild -r -Is checkers,utils -pkgs yojson,unix cwe_checker.plugin; \
    bapbundle install cwe_checker.plugin;
ENTRYPOINT ["opam", "config", "exec", "--"]
