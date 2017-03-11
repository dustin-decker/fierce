FROM python:3.6-alpine

# Set timezone. Get some certs.
RUN apk add --update --no-cache tzdata ca-certificates && update-ca-certificates
ENV TZ=America/Chicago
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

COPY * /fierce/

WORKDIR /fierce

RUN pip3 install -r requirements.txt

RUN adduser -D -u 99666 -s /usr/sbin/nologin user

USER 99666

ENTRYPOINT [ "python3", "fierce.py" ]
