package siem

import (
	"fmt"
	"strings"
)

func NormalizeLogs(raw []string) []map[string]any {
	events := make([]map[string]any, 0, len(raw))
	for _, line := range raw {
		severity := "info"
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "failed") || strings.Contains(lower, "denied"):
			severity = "warning"
		case strings.Contains(lower, "malware") || strings.Contains(lower, "sql injection") || strings.Contains(lower, "bruteforce"):
			severity = "critical"
		}
		events = append(events, map[string]any{
			"message":  line,
			"severity": severity,
		})
	}
	return events
}

func Correlate(events []any) map[string]any {
	failedLogins := 0
	critical := 0
	sources := map[string]int{}
	for _, item := range events {
		event, ok := item.(map[string]any)
		if !ok {
			continue
		}
		message := strings.ToLower(fmt.Sprint(event["message"]))
		if strings.Contains(message, "failed login") {
			failedLogins++
		}
		if event["severity"] == "critical" {
			critical++
		}
		src := fmt.Sprint(event["source_ip"])
		if src != "" && src != "<nil>" {
			sources[src]++
		}
	}
	return map[string]any{
		"failed_logins": failedLogins,
		"critical":      critical,
		"sources":       sources,
	}
}

func DetectAttack(correlation map[string]any) map[string]any {
	score := 0
	reasons := []string{}
	if failed, ok := correlation["failed_logins"].(float64); ok && failed >= 3 {
		score += 55
		reasons = append(reasons, "multiple failed logins")
	}
	if critical, ok := correlation["critical"].(float64); ok && critical > 0 {
		score += 40
		reasons = append(reasons, "critical security event")
	}
	attackType := "none"
	if score >= 80 {
		attackType = "high-risk intrusion"
	} else if score >= 50 {
		attackType = "bruteforce"
	}
	return map[string]any{
		"attack_detected": score >= 50,
		"risk_score":      score,
		"attack_type":     attackType,
		"reasons":         reasons,
	}
}
