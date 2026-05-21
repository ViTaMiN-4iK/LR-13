$body = @{
  source_ip = "203.0.113.17"
  host = "vpn-gateway-17"
  raw_logs = @(
    "failed login for admin from 203.0.113.17",
    "failed login for root from 203.0.113.17",
    "failed login for backup from 203.0.113.17",
    "malware signature detected on vpn-gateway-17"
  )
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:8000/tasks/siem" -Body $body -ContentType "application/json"

