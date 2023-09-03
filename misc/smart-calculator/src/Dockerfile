FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN apt-get update \
    && apt-get install -y curl \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash \
    && apt-get install -y nodejs --fix-missing \
    && rm -r /var/lib/apt/lists/*

ENV FLAG=DUCTF{i_l0v3_eVaL}

COPY app.js /home/ctf/chal/pwn
RUN chmod +x /home/ctf/chal/pwn
