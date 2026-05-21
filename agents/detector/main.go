package main

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"time"

	"lab13-siem-mas/internal/siem"

	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel"
)

const agentName = "attack-detector"

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

	_, _ = nc.Subscribe("siem.auction.bid_request", func(msg *nats.Msg) {
		var req siem.BidRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return
		}
		if req.Type != "detect_attack" {
			return
		}
		bid := siem.Bid{
			TaskID:     req.TaskID,
			Agent:      agentName,
			Cost:       10 + rand.Float64()*5,
			Skill:      0.92,
			Available:  true,
			Subject:    "siem.attacks.detect",
			Reason:     "specialized SIEM attack rules",
			ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		}
		_ = msg.Respond(siem.MustJSON(bid))
	})

	_, err = nc.QueueSubscribe("siem.attacks.detect", "detectors", func(msg *nats.Msg) {
		_, span := otel.Tracer(agentName).Start(ctx, "detect_attack")
		defer span.End()
		task, err := siem.DecodeTask(msg.Data)
		if err != nil {
			log.Println("decode task:", err)
			return
		}
		correlation, _ := task.Payload["correlation"].(map[string]any)
		detection := siem.DetectAttack(correlation)
		result := siem.ResultOK(task, agentName, map[string]any{"detection": detection})
		_ = nc.Publish("siem.audit.events", siem.MustJSON(result))
		task.Payload["detection"] = detection
		task.Type = "block_traffic"
		_ = nc.Publish("siem.traffic.block", siem.MustJSON(task))
		log.Printf("task=%s detection=%v", task.ID, detection)
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println(agentName, "listening on siem.attacks.detect")
	siem.WaitForShutdown()
}
