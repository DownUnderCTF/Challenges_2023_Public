FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN pip install -t /lib/python3/dist-packages pycryptodome

COPY ./private/ /home/ctf/chal/private/
COPY ./public/ /home/ctf/chal/public/
COPY ./flag.txt /home/ctf/chal/flag.txt
COPY ./server.py /home/ctf/chal/pwn
