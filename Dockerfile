# based on https://github.com/BinaryAnalysisPlatform/bap/blob/master/docker/Dockerfile
FROM phusion/baseimage:0.11

RUN apt-get -y update \
    && install_clean sudo \
    && useradd -m bap \
    && echo "bap:bap" | chpasswd \
    && adduser bap sudo \
    && sed -i.bkp -e 's/%sudo\s\+ALL=(ALL\(:ALL\)\?)\s\+ALL/%sudo ALL=NOPASSWD:ALL/g' /etc/sudoers
USER bap
WORKDIR /home/bap
ENV PATH="/home/bap/.opam/4.05.0/bin/:${PATH}"
COPY . /home/bap/cwe_checker/

RUN sudo apt-get -y update \
    && sudo install_clean \
        binutils-multiarch \
        build-essential \
        clang \
        curl \
        git \
        libgmp-dev \
        libx11-dev \
        libzip-dev \
        llvm-6.0-dev \
        m4 \
        pkg-config \
        software-properties-common \
        unzip \
        wget \
        zlib1g-dev \
    && wget https://raw.githubusercontent.com/ocaml/opam/master/shell/install.sh \
    && yes /usr/local/bin | sudo sh install.sh \
# install Bap
    && opam init --auto-setup --comp=4.05.0 --disable-sandboxing --yes \
    && git clone -b testing --depth 1 https://github.com/BinaryAnalysisPlatform/opam-repository.git \
    && opam repo add bap opam-repository \
    && opam update \
    && opam install depext --yes \
    && OPAMJOBS=1 opam depext --install bap --yes \
# install CWE_Checker and dependencies
    && OPAMJOBS=1 opam install yojson alcotest --yes \
    && sudo chown -R bap:bap /home/bap/cwe_checker \
    && cd /home/bap/cwe_checker/src \
    && bapbuild -r -Is checkers,utils -pkgs yojson,unix cwe_checker.plugin \
    && bapbundle install cwe_checker.plugin \
    && sudo apt-get remove -y \
        build-essential \
        clang \
        curl \
        gcc \
        g++ \
        git \
        libgmp-dev \
        libx11-dev \
        libzip-dev \
        llvm-6.0-dev \
        unzip \
        wget \
        zlib1g-dev \
    && sudo apt-get -y autoremove \
    && sudo apt-get -y clean \
    && rm -rf /home/bap/.opam/4.05.0/.opam-switch/sources

WORKDIR /home/bap/cwe_checker/src

ENTRYPOINT ["opam", "config", "exec", "--"]
