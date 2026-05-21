package main

import (
	"context"
	"fmt"
	"log"

	"lab13-siem-mas/internal/siem"

	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel"
)

const agentName = "log-collector"

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

	_, err = nc.QueueSubscribe("siem.logs.collect", "log-collectors", func(msg *nats.Msg) {
		_, span := otel.Tracer(agentName).Start(ctx, "collect_logs")
		defer span.End()
		task, err := siem.DecodeTask(msg.Data)
		if err != nil {
			log.Println("decode task:", err)
			return
		}
		raw, _ := task.Payload["raw_logs"].([]any)
		lines := make([]string, 0, len(raw))
		for _, line := range raw {
			lines = append(lines, fmt.Sprint(line))
		}
		events := siem.NormalizeLogs(lines)
		for i := range events {
			if task.Payload["source_ip"] != nil {
				events[i]["source_ip"] = task.Payload["source_ip"]
			}
			events[i]["host"] = task.Payload["host"]
		}
		result := siem.ResultOK(task, agentName, map[string]any{"events": events})
		_ = nc.Publish("siem.audit.events", siem.MustJSON(result))
		task.Payload["events"] = events
		task.Type = "correlate_events"
		_ = nc.Publish("siem.events.correlate", siem.MustJSON(task))
		log.Printf("task=%s normalized_events=%d", task.ID, len(events))
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println(agentName, "listening on siem.logs.collect")
	siem.WaitForShutdown()
}
