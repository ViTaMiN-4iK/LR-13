package main

import (
	"context"
	"log"

	"lab13-siem-mas/internal/siem"

	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel"
)

const agentName = "event-correlator"

func main() {
	closeLog := siem.SetupLogging(agentName)
	defer closeLog()
	ctx := context.Background()
	shutdown, err := siem.InitTracer(ctx, agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer shutdown(ctx)

	nc, err := siem.ConnectNATS()
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	_, err = nc.QueueSubscribe("siem.events.correlate", "correlators", func(msg *nats.Msg) {
		_, span := otel.Tracer(agentName).Start(ctx, "correlate_events")
		defer span.End()
		task, err := siem.DecodeTask(msg.Data)
		if err != nil {
			log.Println("decode task:", err)
			return
		}
		events, _ := task.Payload["events"].([]any)
		correlation := siem.Correlate(events)
		result := siem.ResultOK(task, agentName, map[string]any{"correlation": correlation})
		_ = nc.Publish("siem.audit.events", siem.MustJSON(result))
		task.Payload["correlation"] = correlation
		task.Type = "detect_attack"
		_ = nc.Publish("siem.attacks.detect", siem.MustJSON(task))
		log.Printf("task=%s correlation=%v", task.ID, correlation)
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println(agentName, "listening on siem.events.correlate")
	siem.WaitForShutdown()
}
