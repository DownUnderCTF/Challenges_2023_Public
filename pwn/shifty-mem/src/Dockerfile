FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update && \
    apt-get -y install bash socat --fix-missing && \
    apt-get -y upgrade

RUN groupadd ctf && useradd -m -g ctf ctf
RUN printf "/bin/bash\n" | chsh ctf

COPY shifty_mem /home/ctf/chal/shifty_mem
RUN chmod 555 /home/ctf/chal/shifty_mem
RUN chown root:root /home/ctf/chal/shifty_mem
RUN chmod u+s /home/ctf/chal/shifty_mem

COPY flag.txt /home/ctf/chal/flag.txt
RUN chmod 440 /home/ctf/chal/flag.txt
RUN chown root:root /home/ctf/chal/flag.txt

USER ctf

ENTRYPOINT socat -dd TCP4-LISTEN:1337,fork,reuseaddr EXEC:"timeout 180 /bin/bash -i",stderr,pty,sane
