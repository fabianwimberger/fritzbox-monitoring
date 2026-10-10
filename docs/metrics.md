# Metrics

## DOCSIS Upstream

| Metric | Labels | Description |
|--------|--------|-------------|
| `fritzbox_docsis_upstream_power_level_dbmv` | `channel_id` | Upstream power level (dBmV) |
| `fritzbox_docsis_upstream_frequency_hz` | `channel_id` | Upstream frequency (Hz) |
| `fritzbox_docsis_upstream_modulation_qam` | `channel_id` | Upstream modulation (QAM) |
| `fritzbox_docsis_upstream_multiplex_info` | `channel_id`, `multiplex` | Multiplex method (ATDMA/SCDMA/TDMA) |

## DOCSIS Downstream

| Metric | Labels | Description |
|--------|--------|-------------|
| `fritzbox_docsis_downstream_power_level_dbmv` | `channel_id` | Downstream power level (dBmV) |
| `fritzbox_docsis_downstream_frequency_hz` | `channel_id` | Downstream frequency (Hz) |
| `fritzbox_docsis_downstream_modulation_qam` | `channel_id` | Downstream modulation (QAM) |
| `fritzbox_docsis_downstream_snr_db` | `channel_id` | Signal-to-noise ratio (dB) |
| `fritzbox_docsis_downstream_latency_ms` | `channel_id` | Downstream latency (ms) |
| `fritzbox_docsis_downstream_corrected_errors_total` | `channel_id` | Corrected errors (Counter) |
| `fritzbox_docsis_downstream_uncorrected_errors_total` | `channel_id` | Uncorrected errors (Counter) |
| `fritzbox_up` | none | `1` when the last FritzBox DOCSIS scrape succeeded |
| `fritzbox_scrape_duration_seconds` | none | Duration of the last FritzBox scrape |

## Connection Speeds

| Metric | Description |
|--------|-------------|
| `fritzbox_connection_upload_speed_bps` | Current upload speed (bps) |
| `fritzbox_connection_download_speed_bps` | Current download speed (bps) |
| `fritzbox_connection_upload_max_bps` | Max upload link rate (bps) |
| `fritzbox_connection_download_max_bps` | Max download link rate (bps) |

## Ping

| Metric | Labels | Description |
|--------|--------|-------------|
| `fritzbox_ping_rtt_avg_ms` | `target` | Average RTT (ms) |
| `fritzbox_ping_rtt_min_ms` | `target` | Min RTT (ms) |
| `fritzbox_ping_rtt_max_ms` | `target` | Max RTT (ms) |

## LAN Hosts

| Metric | Labels | Description |
|--------|--------|-------------|
| `fritzbox_lan_host` | `mac`, `name`, `ip`, `interface` | `1` when the FritzBox reports the host as active, otherwise `0` |
