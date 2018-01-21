# there's not really a good reason to run this in a docker container because it's pure python
#FROM python:2
#CMD python2.7 /opt/FakeDns/FakeDns.py -c dns.conf.example
#COPY . /opt/FakeDns/
#EXPOSE 53

# this docker would simulate a running instance of the tunnel system in order to test.

FROM ubuntu
COPY . /opt/FakeDns/
RUN /bin/bash -c 'apt-get update && apt-get -y install python-libpcap iproute2 nano python2.7; cd /opt/FakeDns/; python2.7 setup.py install'
CMD cd /opt/FakeDns/; python2.7 /opt/FakeDns/FakeDns.py -c dns.conf.example
EXPOSE 53

#docker run -it --privileged -P <container> /bin/bash
