FROM python:3.10-slim-bullseye

RUN apt update && \
    apt install -y --no-install-recommends python3-dev libffi-dev && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install fastapi[all] slowapi geopy

COPY main.py /srv/main.py
WORKDIR /srv

CMD ["uvicorn", "--host", "0.0.0.0", "--port", "1337", "main:app"]