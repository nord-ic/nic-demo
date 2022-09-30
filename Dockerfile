# FROM scratch
FROM ubuntu:latest AS runner

ARG USER=nic
ARG app=nic-demo

USER root
RUN useradd -u 1400 $USER
RUN mkdir /config
RUN mkdir /certs
#RUN mkdir /cacert
COPY ./config/config-${app}.json /config/config-${app}.json
COPY ./certs/*.* /certs/
# RUN chown $USER: ${app} 
RUN chown -R $USER: /config /certs

FROM scratch

ARG USER=nic
ARG app=nic-demo

COPY --from=runner /etc/passwd /etc/passwd
COPY --from=runner /etc/group /etc/group

COPY --from=runner --chown=$USER /config ./config
COPY --from=runner --chown=$USER /certs ./certs
COPY $app ./$app
#COPY --from=runner --chown=$USER $app ./$app

EXPOSE 8080 8080

USER $USER
CMD [ "./nic-demo" ]