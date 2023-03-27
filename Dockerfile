FROM alpine

RUN apk add openssl

ADD ca /opt/ca

ADD bin /root/bin

WORKDIR /root

ENTRYPOINT ["bin/pki.sh"]
