FROM alpine:3.24.1 as builder

WORKDIR /go/src/github.com/systemli/prometheus-dnssec-exporter

ENV USER=appuser
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

RUN apk add --no-cache --update ca-certificates

FROM scratch

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY prometheus-dnssec-exporter /prometheus-dnssec-exporter

USER appuser:appuser

EXPOSE 9204

ENTRYPOINT ["/prometheus-dnssec-exporter"]
