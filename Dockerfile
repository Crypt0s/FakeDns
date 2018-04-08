FROM ubuntu:16.04
COPY . /opt/FakeDns/
WORKDIR /opt/FakeDns/
RUN apt-get update && apt-get install python
CMD python fakedns.py -c dns.conf.example & python testing/tests/run_tests.py
