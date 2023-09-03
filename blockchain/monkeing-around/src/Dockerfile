FROM ghcr.io/downunderctf/docker-vendor/ethcompiler:foundry as build

RUN /root/.foundry/bin/forge install openzeppelin/openzeppelin-contracts@v4.9.3 --no-git
COPY src/ src/
COPY remappings.txt remappings.txt
RUN /root/.foundry/bin/forge build

FROM ghcr.io/downunderctf/eth-challenge-base/eth-challenge:latest as dist

WORKDIR /app

COPY challenge.yaml challenge.yaml
COPY src/ contracts/
# Contract builds output to be in a flat dir
COPY --from=build out/**/* output/

ENV CONTRACT_ABI_DIR=/app/output
