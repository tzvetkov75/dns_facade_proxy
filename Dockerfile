#
#  domain facade image 
FROM python:3

WORKDIR /usr/src/app

COPY domain_facade.py ./
RUN pip install --no-cache-dir dnslib

EXPOSE 53/tcp
EXPOSE 53/udp

CMD [ "python", "./domain_facade.py","-h" ] 




