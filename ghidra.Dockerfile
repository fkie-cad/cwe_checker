FROM fkiecad/cwe_checker_travis_docker_image:ghidra

COPY . /home/cwe/cwe_checker/

RUN sudo chown -R cwe:cwe /home/cwe/cwe_checker \
    && cd /home/cwe/cwe_checker \
    && make all GHIDRA_PATH=/home/cwe/ghidra \
    && cargo clean

WORKDIR /home/cwe/cwe_checker

# ENTRYPOINT ["/bin/sh", "-c"]
CMD cwe_checker /tmp/input
