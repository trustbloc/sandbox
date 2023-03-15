#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
	gcc \
	musl-dev \
	git \
	libtool \
	bash \
	make;
ADD . /opt/workspace/sandbox
WORKDIR /opt/workspace/sandbox
ENV EXECUTABLES go git

FROM golang as sandbox
RUN make issuer-rest


FROM alpine:${ALPINE_VER}
LABEL org.opencontainers.image.source https://github.com/trustbloc/sandbox

RUN apk add --no-cache \
    bash \
    curl \
    jq;

# copy build artifacts from build container
COPY --from=sandbox /opt/workspace/sandbox/.build/bin/issuer /usr/local/bin

WORKDIR /usr/local/bin
ENTRYPOINT ["issuer-rest"]
