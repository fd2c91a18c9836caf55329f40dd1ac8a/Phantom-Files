# Cупер-легкий Alpine Linux (весит 5 МБ)
FROM alpine:latest

RUN apk add --no-cache tcpdump strace net-tools bash coreutils

WORKDIR /evidence

# По умолчанию запускаем tcpdump, чтобы слушать трафик
# (Это можно переопределить в Python-коде)
CMD ["/bin/sh"]