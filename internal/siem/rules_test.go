package siem

import "testing"

func TestNormalizeLogsAssignsSeverity(t *testing.T) {
	events := NormalizeLogs([]string{
		"user login ok",
		"failed login for admin",
		"malware signature detected",
	})
	if events[0]["severity"] != "info" {
		t.Fatalf("expected info, got %v", events[0]["severity"])
	}
	if events[1]["severity"] != "warning" {
		t.Fatalf("expected warning, got %v", events[1]["severity"])
	}
	if events[2]["severity"] != "critical" {
		t.Fatalf("expected critical, got %v", events[2]["severity"])
	}
}

func TestCorrelateCountsFailedLoginsAndCriticalEvents(t *testing.T) {
	result := Correlate([]any{
		map[string]any{"message": "failed login for root", "severity": "warning", "source_ip": "203.0.113.17"},
		map[string]any{"message": "failed login for admin", "severity": "warning", "source_ip": "203.0.113.17"},
		map[string]any{"message": "malware signature", "severity": "critical", "source_ip": "203.0.113.17"},
	})
	if result["failed_logins"] != 2 {
		t.Fatalf("expected 2 failed logins, got %v", result["failed_logins"])
	}
	if result["critical"] != 1 {
		t.Fatalf("expected 1 critical event, got %v", result["critical"])
	}
}

func TestDetectAttackRaisesRiskForBruteforce(t *testing.T) {
	result := DetectAttack(map[string]any{
		"failed_logins": float64(3),
		"critical":      float64(1),
	})
	if result["attack_detected"] != true {
		t.Fatalf("expected attack detection")
	}
	if result["attack_type"] != "high-risk intrusion" {
		t.Fatalf("expected high-risk intrusion, got %v", result["attack_type"])
	}
}
