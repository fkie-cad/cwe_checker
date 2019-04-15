FROM fkiecad/cwe_checker_travis_docker_image:latest

COPY . /home/bap/cwe_checker/

RUN sudo chown -R bap:bap /home/bap/cwe_checker \
    && cd /home/bap/cwe_checker/src \
    && make all

WORKDIR /home/bap/cwe_checker/src

ENTRYPOINT ["opam", "config", "exec", "--"]
