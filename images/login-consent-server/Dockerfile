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
ADD . /opt/workspace/edge-sandbox
WORKDIR /opt/workspace/edge-sandbox
ENV EXECUTABLES go git

FROM golang as edge-sandbox
RUN make login-consent-server


FROM alpine:${ALPINE_VER} as base
COPY --from=edge-sandbox /opt/workspace/edge-sandbox/.build/bin/login-consent /usr/local/bin
WORKDIR /usr/local/bin
ENTRYPOINT ["server"]
