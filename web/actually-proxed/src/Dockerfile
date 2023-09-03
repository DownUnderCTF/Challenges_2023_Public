FROM golang:1.20-alpine3.17

WORKDIR /app

COPY . ./

RUN go build -o out/ ./...
USER 1000:1000
ENV FLAG=DUCTF{y0ur_c0d3_15_n07_b3773r_7h4n_7h3_574nd4rd_l1b}
EXPOSE 1337

ENTRYPOINT [ "./docker-entrypoint.sh" ]
