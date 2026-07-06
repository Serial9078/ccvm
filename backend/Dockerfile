FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y wget unzip ca-certificates && \
    wget https://github.com/projectdiscovery/nuclei/releases/download/v3.10.0/nuclei_3.10.0_linux_amd64.zip && \
    unzip nuclei_3.10.0_linux_amd64.zip && \
    mv nuclei /usr/local/bin/nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f nuclei_3.10.0_linux_amd64.zip && \
    apt-get clean

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
