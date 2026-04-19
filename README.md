# DevSecOps Project

## How to verify monitoring stack

### Start the stack
```bash
cd ~/monitoring && docker-compose up -d
```

### Check all targets are UP
Open: http://YOUR_IP:9090/targets
All jobs must show state = UP

### Check Grafana dashboard
Open: http://YOUR_IP:3000
Login: admin / admin123
Dashboard: Node Exporter Full (ID 1860)

### Check Alertmanager
Open: http://YOUR_IP:9093

### Check Pushgateway
Open: http://YOUR_IP:9091
