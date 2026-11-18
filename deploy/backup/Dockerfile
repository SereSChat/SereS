# Small helper that backs up the SereS database (see backup.sh).
FROM alpine:3.21
RUN apk add --no-cache sqlite
COPY backup.sh /usr/local/bin/backup.sh
ENTRYPOINT ["/usr/local/bin/backup.sh"]
