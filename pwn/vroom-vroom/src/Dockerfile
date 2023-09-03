FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV JAIL_CWD=/chal TMP_ENABLED=1
COPY nsjail.cfg /home/ctf/nsjail.cfg

COPY flag.txt /home/ctf/chal/flag.txt

COPY run.py /home/ctf/chal/pwn
COPY d8 /home/ctf/chal/d8
COPY snapshot_blob.bin /home/ctf/chal/snapshot_blob.bin

