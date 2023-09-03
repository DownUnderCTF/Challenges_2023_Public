FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV JAIL_CWD=/chal
ENV TMP_ENABLED=1

COPY ./flag.txt /home/ctf/chal/flag.txt

COPY ./pwn /home/ctf/chal/pwn
COPY ./js.tar.gz /home/ctf/chal/js.tar.gz
RUN tar xzf /home/ctf/chal/js.tar.gz -C /home/ctf/chal/

RUN mv /home/ctf/chal/flag.txt /home/ctf/chal/$(tr -dc a-z0-9 </dev/urandom | head -c 32)_flag.txt
