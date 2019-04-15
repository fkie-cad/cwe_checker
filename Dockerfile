FROM fkiecad/cwe_checker_travis_docker_image:latest

COPY . /home/bap/cwe_checker/

RUN sudo chown -R bap:bap /home/bap/cwe_checker \
    && cd /home/bap/cwe_checker/src \
    && bapbuild -r -Is checkers,utils -pkgs yojson,unix cwe_checker.plugin \
    && bapbundle install cwe_checker.plugin

WORKDIR /home/bap/cwe_checker/src

ENTRYPOINT ["opam", "config", "exec", "--"]
