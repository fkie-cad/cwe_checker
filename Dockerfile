FROM rust:1.63 AS builder

WORKDIR /cwe_checker

COPY . .
RUN cargo build --release

FROM fkiecad/ghidra_headless_base:10.2.2 as runtime

RUN apt-get -y update \
    && apt-get -y install sudo \
    && useradd -m cwe \
    && echo "cwe:cwe" | chpasswd \
    && adduser cwe sudo \
    && sed -i.bkp -e 's/%sudo\s\+ALL=(ALL\(:ALL\)\?)\s\+ALL/%sudo ALL=NOPASSWD:ALL/g' /etc/sudoers
USER cwe

# Install all necessary files from the builder stage
COPY --from=builder /cwe_checker/target/release/cwe_checker /home/cwe/cwe_checker
COPY --from=builder /cwe_checker/src/config.json /home/cwe/.config/cwe_checker/config.json
COPY --from=builder /cwe_checker/src/ghidra/p_code_extractor /home/cwe/.local/share/cwe_checker/ghidra/p_code_extractor
RUN echo "{ \"ghidra_path\": \"/opt/ghidra\" }" | sudo tee /home/cwe/.config/cwe_checker/ghidra.json

WORKDIR /

ENTRYPOINT ["/home/cwe/cwe_checker"]
