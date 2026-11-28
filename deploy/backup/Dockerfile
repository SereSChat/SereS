# Small helper that backs up the SereS database (see backup.sh).
FROM alpine:3.21
RUN apk add --no-cache sqlite
COPY --chmod=755 backup.sh /usr/local/bin/backup.sh
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/backup.sh"]
