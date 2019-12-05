FROM fkiecad/cwe_checker_travis_docker_image:v0.3

COPY . /home/bap/cwe_checker/

RUN sudo chown -R bap:bap /home/bap/cwe_checker \
    && cd /home/bap/cwe_checker \
    && make all

WORKDIR /home/bap/cwe_checker

ENTRYPOINT ["opam", "config", "exec", "--"]
