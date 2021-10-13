# syntax=docker/dockerfile:1

FROM python:3.8
RUN apt-get update && apt-get install -y inetutils-ping iproute2 iptables tcpdump iperf3 libpcap0.8-dev
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
CMD [ "sleep", "infinity" ]
