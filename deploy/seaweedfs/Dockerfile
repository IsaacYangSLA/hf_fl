# SeaweedFS 4.47 plus the narrowly scoped Exchange compatibility patch.
FROM golang@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS builder
ENV CGO_ENABLED=0 GOMAXPROCS=4
WORKDIR /src
RUN curl -fsSL https://codeload.github.com/seaweedfs/seaweedfs/tar.gz/c5073360007d28385a33426a42ac3e4ec504c5a3 -o /tmp/source.tar.gz \
    && echo '3700416b287d03912506955dacf4f0a1d4f89cb44806e39e7cc572d2259407a4  /tmp/source.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/source.tar.gz --strip-components=1 \
    && rm /tmp/source.tar.gz
RUN go mod download
COPY seaweedfs-4.47-exchange.patch /tmp/exchange.patch
RUN git apply --check /tmp/exchange.patch && git apply /tmp/exchange.patch \
    && go test -p 4 ./weed/s3api -run '^TestHF2L' -count=1 \
    && go build -p 4 -trimpath \
       -ldflags='-X github.com/seaweedfs/seaweedfs/weed/util/version.COMMIT=c50733600-hf2l1' \
       -o /out/weed ./weed

FROM chrislusf/seaweedfs@sha256:ce9e796f1fe6f06968f4c04bdaf8f678dad9c8acdfef3d244133d71bfa6bf882
COPY --from=builder /out/weed /usr/bin/weed
LABEL org.opencontainers.image.source="https://github.com/seaweedfs/seaweedfs" \
      org.opencontainers.image.revision="c5073360007d28385a33426a42ac3e4ec504c5a3" \
      org.hf2l.seaweedfs.patch="exchange-compatibility-1"
COPY --from=builder /src/LICENSE /usr/share/doc/seaweedfs/LICENSE
COPY seaweedfs-4.47-exchange.patch README.md NOTICE /usr/share/doc/seaweedfs/
