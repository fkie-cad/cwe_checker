FROM ubuntu:xenial

RUN apt-get -y update \
    && apt-get install -y sudo \
    && useradd -m cwe \
    && echo "cwe:cwe" | chpasswd \
    && adduser cwe sudo \
    && sed -i.bkp -e 's/%sudo\s\+ALL=(ALL\(:ALL\)\?)\s\+ALL/%sudo ALL=NOPASSWD:ALL/g' /etc/sudoers
    
USER cwe

RUN sudo apt-get install python-pip apt-utils -y

RUN pip install --upgrade pip

RUN pip install scons

ENV PATH="/home/cwe/.local/bin/:${PATH}"

COPY . /home/cwe/artificial_samples/

WORKDIR /home/cwe/artificial_samples/

RUN ./install_cross_compilers.sh

# RUN sudo /home/cwe/.local/bin/scons