FROM scratch

COPY nic-demo /nic-demo

EXPOSE 8080 8080

CMD [ "/nic-demo" ]
