FROM ubuntu:bionic

RUN apt-get -y update \
    && apt-get install -y sudo \
    && useradd -m cwe \
    && echo "cwe:cwe" | chpasswd \
    && adduser cwe sudo \
    && sed -i.bkp -e 's/%sudo\s\+ALL=(ALL\(:ALL\)\?)\s\+ALL/%sudo ALL=NOPASSWD:ALL/g' /etc/sudoers

USER cwe

RUN sudo apt-get install python3-pip apt-utils -y

RUN pip3 install --upgrade pip

RUN sudo pip3 install scons

ENV PATH="/home/cwe/.local/bin/:${PATH}"

COPY ./install_cross_compilers.sh .

RUN ./install_cross_compilers.sh

COPY . /home/cwe/artificial_samples/

WORKDIR /home/cwe/artificial_samples/
