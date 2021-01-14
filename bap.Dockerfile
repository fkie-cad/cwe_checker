FROM fkiecad/cwe_checker_travis_docker_image:bap

COPY . /home/cwe/cwe_checker/

RUN sudo chown -R cwe:cwe /home/cwe/cwe_checker \
    && cd /home/cwe/cwe_checker \
    && make with_bap_backend \
    && cargo clean \
    && dune clean

WORKDIR /home/cwe/cwe_checker

ENTRYPOINT ["opam", "config", "exec", "--"]
CMD cwe_checker /tmp/input
