package siem

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

func Env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func ConnectNATS() (*nats.Conn, error) {
	return nats.Connect(Env("NATS_URL", nats.DefaultURL), nats.Name(Env("AGENT_NAME", "siem-agent")))
}

func InitTracer(ctx context.Context, service string) (func(context.Context) error, error) {
	endpoint := Env("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4318")
	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(endpoint), otlptracehttp.WithInsecure())
	if err != nil {
		return nil, err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(service),
		)),
	)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

func WaitForShutdown() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutdown signal received")
	time.Sleep(300 * time.Millisecond)
}
