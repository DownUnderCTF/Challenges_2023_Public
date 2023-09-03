FROM python:3.10

WORKDIR /
COPY mini_dns_server.py .
COPY flag.txt flag.txt

RUN pip3 install dnslib

CMD ["python3", "mini_dns_server.py"]
