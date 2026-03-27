# Elastic Stack Setup Guide

**Version**: Elastic Stack 8.x  
**Author**: Chandra Sekhar Chakraborty  

---

## Prerequisites

| Component | Version | Notes |
|-----------|---------|-------|
| Elastic Stack | 8.12+ | All-in-one self-managed or Elastic Cloud |
| RAM | 8 GB minimum | 16 GB recommended |
| Disk | 50 GB minimum | SSD preferred |
| OS | Ubuntu 22.04 LTS | Or any systemd-based Linux |
| Java | Bundled with ES 8.x | No manual install needed |

---

## 1. Install Elasticsearch

```bash
# Import Elastic GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Install
sudo apt-get update && sudo apt-get install elasticsearch -y

# Start and enable
sudo systemctl enable elasticsearch --now

# Verify
curl -s --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic:$ES_PASSWORD https://localhost:9200 | python3 -m json.tool
```

## 2. Install Kibana

```bash
sudo apt-get install kibana -y
sudo systemctl enable kibana --now

# Generate enrollment token from Elasticsearch
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

# Complete setup at: http://localhost:5601
# Enter the enrollment token when prompted
```

## 3. Install Fleet Server + Elastic Agent

```bash
# Download Elastic Agent
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.12.0-linux-x86_64.tar.gz
tar xzvf elastic-agent-8.12.0-linux-x86_64.tar.gz

# In Kibana: Fleet → Add Fleet Server
# Copy the enrollment command and run it:
sudo ./elastic-agent install \
  --fleet-server-es=https://localhost:9200 \
  --fleet-server-service-token=<token> \
  --fleet-server-policy=fleet-server-policy \
  --certificate-authorities=/etc/elasticsearch/certs/http_ca.crt
```

## 4. Enable Security Features

```bash
# In Kibana → Security → Detections
# 1. Enable detections
# 2. Set up index patterns: logs-endpoint.events.*, winlogbeat-*
# 3. Install prebuilt rules (optional)

# Via API:
curl -X POST "https://localhost:5601/api/detection_engine/index" \
  -H "kbn-xsrf: true" \
  -H "Authorization: ApiKey <id>:<key>"
```

## 5. Create API Key for Rule Deployment

```bash
curl -X POST "https://localhost:9200/_security/api_key" \
  -H "Content-Type: application/json" \
  -u elastic:$ES_PASSWORD \
  -d '{
    "name": "detection-lab-deployer",
    "role_descriptors": {
      "detection_engineer": {
        "cluster": ["monitor"],
        "indices": [{"names": [".siem-signals-*"], "privileges": ["all"]}],
        "applications": [{
          "application": "kibana-.kibana",
          "privileges": ["feature_siem.all"],
          "resources": ["*"]
        }]
      }
    }
  }'
```

## 6. Configure Index Patterns

Enable the following index patterns in Kibana:
- `logs-endpoint.events.*` — Elastic Agent endpoint events
- `winlogbeat-*` — Winlogbeat Windows event logs
- `logs-windows.*` — Windows integration logs
- `.siem-signals-*` — Detection alerts

---

## Kibana Security Dashboard Setup

1. Navigate to **Security → Overview**
2. Import dashboard JSON from `dashboards/kibana_soc_dashboard.json`
3. Set default time range to **Last 24 hours**
4. Pin dashboard to Security workspace

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Elasticsearch won't start | Check `journalctl -u elasticsearch` for heap/disk errors |
| Kibana can't connect | Verify `elasticsearch.hosts` in `/etc/kibana/kibana.yml` |
| No events in SIEM | Check Fleet agent enrollment and policy assignment |
| Rule not triggering | Verify index pattern covers data source |
