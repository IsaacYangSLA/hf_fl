# Build the native services without Python or a runtime compiler.
# Image pins match examples/first_federation/images.example.json.
FROM golang:1.26.8-bookworm@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107 AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOSUMDB=sum.golang.org GOMAXPROCS=4
WORKDIR /src
COPY packages/exchange/go.mod packages/exchange/go.sum ./packages/exchange/
COPY packages/jobs/go.mod packages/jobs/go.sum ./packages/jobs/
RUN go -C packages/exchange mod download \
    && go -C packages/exchange mod verify \
    && go -C packages/jobs mod download \
    && go -C packages/jobs mod verify
COPY packages/exchange ./packages/exchange
COPY packages/jobs ./packages/jobs
RUN mkdir -p /out \
    && go -C packages/exchange build -p 4 -mod=readonly -trimpath -buildvcs=false \
       -o /out/hf2l-exchange ./cmd/hf2l-exchange \
    && go -C packages/jobs build -p 4 -mod=readonly -trimpath -buildvcs=false \
       -o /out/hf2l-jobs ./cmd/hf2l-jobs

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
LABEL org.opencontainers.image.source="https://github.com/IsaacYangSLA/hf_fl"
COPY --from=build /out/hf2l-exchange /usr/local/bin/hf2l-exchange
COPY --from=build /out/hf2l-jobs /usr/local/bin/hf2l-jobs
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN chmod 0755 /usr/local/bin/hf2l-exchange /usr/local/bin/hf2l-jobs
ENV HOME=/tmp
WORKDIR /tmp
USER 10001:10001
# No ENTRYPOINT: Compose maintenance commands select the executable explicitly.
CMD ["/usr/local/bin/hf2l-exchange", "--help"]
