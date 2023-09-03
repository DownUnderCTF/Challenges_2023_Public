FROM golang:1.20-alpine3.17

WORKDIR /app

COPY . ./

RUN go build -o app ./...

EXPOSE 1337
ENV FLAG=DUCTF{17_533m5_w3_f0rg07_70_pr0x}

USER 1000:1000

CMD ["./app"]
