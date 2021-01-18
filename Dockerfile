FROM rust:1.49 AS builder

WORKDIR /cwe_checker

COPY . .
RUN cargo build --release

FROM phusion/baseimage:18.04-1.0.0 as runtime

RUN apt-get -y update \
    && install_clean sudo \
    && useradd -m cwe \
    && echo "cwe:cwe" | chpasswd \
    && adduser cwe sudo \
    && sed -i.bkp -e 's/%sudo\s\+ALL=(ALL\(:ALL\)\?)\s\+ALL/%sudo ALL=NOPASSWD:ALL/g' /etc/sudoers
USER cwe

WORKDIR /home/cwe

ENV PATH="/home/cwe/.cargo/bin/:${PATH}"
ENV GHIDRA_VERSION="9.2.1_PUBLIC"

# Install Ghidra
RUN sudo apt-get -y update \
    && sudo install_clean \
        curl \
        unzip \
        openjdk-11-jdk \
    && curl -fSL https://www.ghidra-sre.org/ghidra_9.2.1_PUBLIC_20201215.zip -o ghidra.zip \
    && unzip -q ghidra.zip \
    && sudo mv ghidra_${GHIDRA_VERSION} /opt/ghidra \
    && rm ghidra.zip

# Install all necessary files from the builder stage
COPY --from=builder /cwe_checker/target/release/cwe_checker /home/cwe/cwe_checker
COPY --from=builder /cwe_checker/src/config.json /home/cwe/.config/cwe_checker/config.json
COPY --from=builder /cwe_checker/ghidra/p_code_extractor /home/cwe/.local/share/cwe_checker/ghidra/p_code_extractor
RUN echo "{ \"ghidra_path\": \"/opt/ghidra\" }" | sudo tee /home/cwe/.config/cwe_checker/ghidra.json

WORKDIR /

ENTRYPOINT ["/home/cwe/cwe_checker"]
