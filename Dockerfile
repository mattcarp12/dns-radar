FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG APP_CMD
RUN go build -o /bin/app ./cmd/${APP_CMD}

FROM alpine:latest
COPY --from=builder /bin/app /bin/app
CMD ["/bin/app"]