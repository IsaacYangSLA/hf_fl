# The public server and worker are native Go programs; Python remains client-side.
FROM golang:1.26.8-bookworm@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107 AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOMAXPROCS=4
WORKDIR /src
COPY packages/exchange/go.mod packages/exchange/go.sum ./packages/exchange/
RUN go -C packages/exchange mod download && go -C packages/exchange mod verify
COPY packages/exchange ./packages/exchange
RUN mkdir -p /out && go -C packages/exchange build -p 4 -mod=readonly -trimpath -buildvcs=false -o /out/hf2l-exchange ./cmd/hf2l-exchange \
    && go version -m /out/hf2l-exchange > /out/exchange-build-info.txt
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
COPY --from=build /out/hf2l-exchange /usr/local/bin/hf2l-exchange
COPY --from=build /out/exchange-build-info.txt /usr/share/hf2l/exchange-build-info.txt
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN chmod 0755 /usr/local/bin/hf2l-exchange
USER 10001:10001
CMD ["hf2l-exchange", "--help"]
