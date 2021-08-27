FROM python:3.8

WORKDIR /opt/FakeDns/tests
COPY ./ /opt/FakeDns/tests
RUN pip install dnspython
CMD python3 -m unittest discover -v /opt/FakeDns/tests