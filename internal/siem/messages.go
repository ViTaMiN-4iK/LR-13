package siem

import (
	"encoding/json"
	"time"
)

type Task struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	TraceID   string         `json:"trace_id"`
	Payload   map[string]any `json:"payload"`
	CreatedAt time.Time      `json:"created_at"`
}

type Result struct {
	TaskID    string         `json:"task_id"`
	TraceID   string         `json:"trace_id"`
	Agent     string         `json:"agent"`
	Success   bool           `json:"success"`
	Output    map[string]any `json:"output"`
	Error     string         `json:"error,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

type BidRequest struct {
	TaskID  string         `json:"task_id"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

type Bid struct {
	TaskID     string  `json:"task_id"`
	Agent      string  `json:"agent"`
	Cost       float64 `json:"cost"`
	Skill      float64 `json:"skill"`
	Available  bool    `json:"available"`
	Subject    string  `json:"subject"`
	Reason     string  `json:"reason"`
	ReceivedAt string  `json:"received_at"`
}

func DecodeTask(data []byte) (Task, error) {
	var task Task
	err := json.Unmarshal(data, &task)
	return task, err
}

func MustJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func ResultOK(task Task, agent string, output map[string]any) Result {
	return Result{
		TaskID:    task.ID,
		TraceID:   task.TraceID,
		Agent:     agent,
		Success:   true,
		Output:    output,
		Timestamp: time.Now().UTC(),
	}
}

func ResultError(task Task, agent string, err error) Result {
	return Result{
		TaskID:    task.ID,
		TraceID:   task.TraceID,
		Agent:     agent,
		Success:   false,
		Error:     err.Error(),
		Timestamp: time.Now().UTC(),
	}
}
