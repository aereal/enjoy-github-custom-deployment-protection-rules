FROM golang:1.21 as build

WORKDIR /go/src/app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION
RUN env CGO_ENABLED=0 GOOS=linux go build -ldflags "-X github.com/aereal/enjoy-github-custom-deployment-protection-rules/webhook.serviceVersion=$VERSION" -o /app ./cmd/webhook

FROM ghcr.io/aereal/otel-collector-dist/lambda_go:add-labels
COPY --from=build /app ${LAMBDA_TASK_ROOT}
ADD ./etc/otel.yml /opt/collector-config/config.yaml

CMD ["app"]
