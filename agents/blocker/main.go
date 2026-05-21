package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"lab13-siem-mas/internal/siem"

	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
)

const agentName = "traffic-blocker"

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

	rdb := redis.NewClient(&redis.Options{Addr: siem.Env("REDIS_ADDR", "localhost:6379")})
	defer rdb.Close()

	_, err = nc.QueueSubscribe("siem.traffic.block", "blockers", func(msg *nats.Msg) {
		_, span := otel.Tracer(agentName).Start(ctx, "block_traffic")
		defer span.End()
		task, err := siem.DecodeTask(msg.Data)
		if err != nil {
			log.Println("decode task:", err)
			return
		}
		detection, _ := task.Payload["detection"].(map[string]any)
		sourceIP := fmt.Sprint(task.Payload["source_ip"])
		blocked := detection["attack_detected"] == true && sourceIP != "" && sourceIP != "<nil>"
		if blocked {
			_ = rdb.SAdd(ctx, "siem:blocked_ips", sourceIP).Err()
			_ = rdb.Incr(ctx, "siem:block_count").Err()
			_ = rdb.Set(ctx, "siem:last_block:"+sourceIP, time.Now().UTC().Format(time.RFC3339), 24*time.Hour).Err()
		}
		output := map[string]any{
			"blocked":         blocked,
			"source_ip":       sourceIP,
			"redis_state_key": "siem:blocked_ips",
			"detection":       detection,
		}
		result := siem.ResultOK(task, agentName, output)
		_ = nc.Publish("siem.audit.events", siem.MustJSON(result))
		_ = nc.Publish("siem.tasks.completed", siem.MustJSON(result))
		log.Printf("task=%s blocked=%t source_ip=%s", task.ID, blocked, sourceIP)
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println(agentName, "listening on siem.traffic.block")
	siem.WaitForShutdown()
}
