FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV JAIL_CWD=/chal
ENV TMP_ENABLED=1
ENV MOUNT_PROC=1
COPY ./flag.txt /home/ctf/chal/flag.txt
COPY ./binary_mail /home/ctf/chal/pwn
