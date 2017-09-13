# this docker would simulate a running instance of the tunnel system in order to test.

FROM ubuntu
RUN /bin/bash -c 'apt-get update && apt-get -y install python2.7; cd /opt;'
CMD python2.7 /opt/FakeDns/tunnel/client.py
COPY . /opt/FakeDns/
EXPOSE 53