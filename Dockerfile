# FROM scratch
FROM alpine

ARG USER=default
ENV HOME=/home/$USER

RUN apk add --update sudo

RUN adduser -D $USER \
    && echo "$USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$USER \
    && chmod 0440 /etc/sudoers.d/$USER

USER $USER
WORKDIR $HOME

RUN mkdir ./config
RUN mkdir ./certs
RUN mkdir ./cacert

COPY ./certs/tls.* ./certs
COPY ./config/*.json ./config
COPY nic-demo ./nic-demo

EXPOSE 8080 8080

CMD [ "./nic-demo" ]
