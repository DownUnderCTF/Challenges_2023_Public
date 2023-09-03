FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

COPY ./flag.txt /home/ctf/chal
COPY ./SimpleFTPServer.py /home/ctf/chal/pwn
RUN chmod +x /home/ctf/chal/pwn