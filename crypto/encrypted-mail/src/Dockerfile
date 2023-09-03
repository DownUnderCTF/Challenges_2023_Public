FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN pip install -t /lib/python3/dist-packages gmpy2

ENV CPU_SHARES_MS=300
ENV TIME_LIMIT=300

COPY ./flag.txt /home/ctf/chal
COPY ./bot_users.py /home/ctf/chal
COPY ./db.py /home/ctf/chal
COPY ./crypto.py /home/ctf/chal
COPY ./server.py /home/ctf/chal/pwn
