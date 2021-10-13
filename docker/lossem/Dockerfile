# syntax=docker/dockerfile:1

FROM python:3.8-slim-buster
WORKDIR /lossem
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
RUN apt-get update && apt-get install -y inetutils-ping iproute2 tcpdump iptables
COPY . .
CMD [ "sleep", "infinity" ]
