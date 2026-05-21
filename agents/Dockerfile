FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY internal ./internal
COPY agents ./agents
ARG AGENT=log_collector
RUN go build -o /out/agent ./agents/${AGENT}

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/agent /app/agent
ENTRYPOINT ["/app/agent"]

