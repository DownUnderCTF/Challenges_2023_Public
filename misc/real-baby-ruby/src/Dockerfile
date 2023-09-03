FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN apt-get update \
	&& apt-get install -y ruby \
	&& rm -rf /var/lib/apt/lists/*

ENV TMP_ENABLED=1

COPY ./flag.txt /home/ctf/chal/flag
COPY ./real-baby.rb /home/ctf/chal/pwn

RUN chmod +x /home/ctf/chal/pwn
