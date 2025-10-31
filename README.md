# FritzBox DOCSIS Cable Monitoring

Prometheus exporter for monitoring FritzBox cable modem (DOCSIS) metrics, connection speeds, and network quality.

## Features

- DOCSIS cable metrics: power levels, frequencies, modulation, SNR, latency per channel
- Error tracking: corrected/uncorrected errors calculated as deltas
- Connection speeds: current and maximum upload/download rates
- Ping statistics: latency and packet loss monitoring
- Optional Home Assistant integration for temperature correlation

## Setup

### Prerequisites

- FritzBox cable modem (e.g., 6690, 6591, 6660)
- Docker and Docker Compose
- Prometheus (configured separately)
- Grafana (optional, for visualization)

### Installation

1. Clone or download this repository

2. Copy the example environment file:
```bash
cp .env.example .env
```

3. Edit `.env` with your FritzBox credentials:
```bash
FRITZBOX_IP=192.168.178.1
FRITZBOX_USER=admin
FRITZBOX_PASSWORD=your_password
PING_TARGET=1.1.1.1
```

4. (Optional) If you use an external reverse-proxy network, uncomment the relevant lines in `docker-compose.yml`

5. Start the exporter:
```bash
docker-compose up -d
```

6. Verify it's running:
```bash
curl http://localhost:8000/metrics
```

### Prometheus Configuration

Add this job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'fritzbox'
    scrape_interval: 30s
    static_configs:
      - targets: ['fritzbox-exporter:8000']
```

Restart Prometheus after making changes.

### Grafana Dashboard

Import `grafana-dashboard.json` to visualize all metrics including power levels, SNR, error rates, and connection speeds.

## Metrics Exposed

### DOCSIS Metrics (per channel)
- `fritzbox_docsis_upstream_power_level_dbmv` - Upstream power in dBmV
- `fritzbox_docsis_upstream_frequency_hz` - Upstream frequency in Hz
- `fritzbox_docsis_upstream_modulation_qam` - Upstream QAM modulation
- `fritzbox_docsis_downstream_power_level_dbmv` - Downstream power in dBmV
- `fritzbox_docsis_downstream_frequency_hz` - Downstream frequency in Hz
- `fritzbox_docsis_downstream_modulation_qam` - Downstream QAM modulation
- `fritzbox_docsis_downstream_snr_db` - Signal-to-noise ratio in dB
- `fritzbox_docsis_downstream_latency_ms` - Latency in milliseconds
- `fritzbox_docsis_downstream_corrected_errors_total` - Corrected errors (counter)
- `fritzbox_docsis_downstream_uncorrected_errors_total` - Uncorrected errors (counter)

### Connection Metrics
- `fritzbox_connection_upload_speed_bps` - Current upload speed
- `fritzbox_connection_download_speed_bps` - Current download speed
- `fritzbox_connection_upload_max_bps` - Maximum upload speed
- `fritzbox_connection_download_max_bps` - Maximum download speed

### Ping Metrics
- `fritzbox_ping_rtt_avg_ms` - Average round-trip time
- `fritzbox_ping_rtt_min_ms` - Minimum round-trip time
- `fritzbox_ping_rtt_max_ms` - Maximum round-trip time
- `fritzbox_ping_packet_loss_percent` - Packet loss percentage


## Optional: Home Assistant Integration

To correlate cable issues with outdoor temperature, add these to your `.env`:

```bash
HOMEASSISTANT_URL=http://homeassistant:8123
HOMEASSISTANT_TOKEN=your_long_lived_access_token
HOMEASSISTANT_ENTITY=sensor.outdoor_temperature
```

## Troubleshooting

**Authentication fails**: Check credentials in `.env` and ensure the user has admin rights on the FritzBox.

**No metrics appear**: Check logs with `docker-compose logs -f fritzbox-exporter` and verify FritzBox is reachable.

**High error rates**: Check your cable signal quality. Downstream power should be -15 to +15 dBmV, upstream 35 to 51 dBmV, and SNR should be > 30 dB.

## License

MIT
