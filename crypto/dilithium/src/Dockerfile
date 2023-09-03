FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV JAIL_CWD=/chal

COPY ./libpqcrystals_dilithium2_ref.so /home/ctf/chal
COPY ./flag.txt /home/ctf/chal
COPY ./pk.bin /home/ctf/chal
COPY ./verifier.py /home/ctf/chal/pwn
