FROM fkiecad/cwe_checker_travis_docker_image:latest

COPY . /home/bap/cwe_checker/

RUN sudo chown -R bap:bap /home/bap/cwe_checker \
    && cd /home/bap/cwe_checker \
    && make all \
    && make clean

WORKDIR /home/bap/cwe_checker

ENTRYPOINT ["opam", "config", "exec", "--"]
CMD cwe_checker /tmp/input
