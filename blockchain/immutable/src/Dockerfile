FROM ghcr.io/downunderctf/docker-vendor/ethcompiler:foundry as build

COPY contracts/ src/
RUN /root/.foundry/bin/forge build


FROM ghcr.io/downunderctf/eth-challenge-base/eth-challenge:latest as dist

WORKDIR /app

COPY challenge.yaml challenge.yaml
COPY contracts/ contracts/
# Contract builds output to be in a flat dir
COPY --from=build out/**/* output/

ENV CONTRACT_ABI_DIR=/app/output
