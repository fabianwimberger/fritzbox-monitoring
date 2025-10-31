#!/usr/bin/env python
"""
FritzBox DOCSIS Cable Monitoring Exporter for Prometheus
Collects cable modem metrics, connection speeds, ping stats, and optional Home Assistant data.
"""

import os
import re
import time
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from prometheus_client import start_http_server, Gauge, Counter, REGISTRY
from pingparsing import PingParsing, PingTransmitter


class FritzboxCollector:
    def __init__(self):
        # ========================================
        # Configuration from environment variables
        # ========================================
        self.fritzbox_ip = os.environ.get("FRITZBOX_IP", "192.168.178.1")
        self.fritzbox_user = os.environ.get("FRITZBOX_USER")
        self.fritzbox_password = os.environ.get("FRITZBOX_PASSWORD")
        self.ping_target = os.environ.get("PING_TARGET", "1.1.1.1")

        # Optional: Home Assistant integration for temperature
        self.homeassistant_url = os.environ.get("HOMEASSISTANT_URL", "")
        self.homeassistant_token = os.environ.get("HOMEASSISTANT_TOKEN", "")
        self.homeassistant_entity = os.environ.get("HOMEASSISTANT_ENTITY", "sensor.outdoor_temperature")

        # ========================================
        # Internal state management
        # ========================================
        # Cache authentication session to reduce FritzBox load
        self._cached_sid = None
        self._sid_timestamp = 0

        # Regex to extract QAM numbers (e.g., "256QAM" -> 256)
        self._qam_pattern = re.compile(r'(\d+)')

        # Track previous error counts for delta calculation
        # FritzBox returns cumulative totals, we need incremental values
        self._previous_corr_errors = {}
        self._previous_uncorr_errors = {}

        # ========================================
        # Prometheus Metrics Definitions
        # ========================================

        # --- DOCSIS Upstream (Upload) Metrics ---
        self.docsis_power_level_up = Gauge('fritzbox_docsis_upstream_power_level_dbmv',
                                           'Upstream power level in dBmV', ['channel_id'])
        self.docsis_frequency_up = Gauge('fritzbox_docsis_upstream_frequency_hz',
                                         'Upstream frequency in Hz', ['channel_id'])
        self.docsis_modulation_up = Gauge('fritzbox_docsis_upstream_modulation_qam',
                                          'Upstream modulation (QAM)', ['channel_id'])
        self.docsis_multiplex_up = Gauge('fritzbox_docsis_upstream_multiplex_info',
                                         'Upstream multiplex method', ['channel_id', 'multiplex'])

        # --- DOCSIS Downstream (Download) Metrics ---
        self.docsis_power_level_down = Gauge('fritzbox_docsis_downstream_power_level_dbmv',
                                             'Downstream power level in dBmV', ['channel_id'])
        self.docsis_frequency_down = Gauge('fritzbox_docsis_downstream_frequency_hz',
                                           'Downstream frequency in Hz', ['channel_id'])
        self.docsis_modulation_down = Gauge('fritzbox_docsis_downstream_modulation_qam',
                                            'Downstream modulation (QAM)', ['channel_id'])
        self.docsis_snr_down = Gauge('fritzbox_docsis_downstream_snr_db',
                                     'Downstream signal-to-noise ratio in dB', ['channel_id'])
        self.docsis_latency_down = Gauge('fritzbox_docsis_downstream_latency_ms',
                                         'Downstream latency in milliseconds', ['channel_id'])
        self.docsis_corr_errors = Counter('fritzbox_docsis_downstream_corrected_errors_total',
                                          'Downstream corrected errors (incremental)', ['channel_id'])
        self.docsis_uncorr_errors = Counter('fritzbox_docsis_downstream_uncorrected_errors_total',
                                            'Downstream uncorrected errors (incremental)', ['channel_id'])

        # --- Connection Speed Metrics ---
        self.connection_upload_speed_bps = Gauge('fritzbox_connection_upload_speed_bps',
                                                 'Current upload speed in bps')
        self.connection_download_speed_bps = Gauge('fritzbox_connection_download_speed_bps',
                                                   'Current download speed in bps')
        self.connection_upload_max_bps = Gauge('fritzbox_connection_upload_max_bps',
                                               'Maximum upload speed in bps')
        self.connection_download_max_bps = Gauge('fritzbox_connection_download_max_bps',
                                                 'Maximum download speed in bps')

        # --- Ping Metrics ---
        self.ping_rtt_avg = Gauge('fritzbox_ping_rtt_avg_ms',
                                  'Ping average round-trip time in ms', ['target'])
        self.ping_rtt_min = Gauge('fritzbox_ping_rtt_min_ms',
                                  'Ping minimum round-trip time in ms', ['target'])
        self.ping_rtt_max = Gauge('fritzbox_ping_rtt_max_ms',
                                  'Ping maximum round-trip time in ms', ['target'])
        self.ping_packet_loss = Gauge('fritzbox_ping_packet_loss_percent',
                                      'Ping packet loss percentage', ['target'])

        # --- Temperature Metric (optional) ---
        self.outdoor_temperature = Gauge('outdoor_temperature_celsius',
                                        'Outdoor temperature from Home Assistant', ['entity_id'])

    def get_sid(self, force_refresh=False):
        """
        Authenticate with FritzBox and get a Session ID (SID).
        Caches the SID for 5 minutes to reduce authentication load.
        """
        current_time = time.time()

        # Return cached SID if still valid (less than 5 minutes old)
        if not force_refresh and self._cached_sid and (current_time - self._sid_timestamp) < 300:
            return self._cached_sid

        try:
            # Step 1: Get authentication challenge from FritzBox
            response = requests.get(f"http://{self.fritzbox_ip}/login_sid.lua", timeout=5)
            challenge = response.text.split("<Challenge>")[1].split("</Challenge>")[0]

            # Step 2: Create MD5 hash response (FritzBox authentication format)
            challenge_response = f"{challenge}-{self.fritzbox_password}"
            md5_hash = hashlib.md5(challenge_response.encode('utf-16le')).hexdigest()

            # Step 3: Send authentication request
            auth_url = f"http://{self.fritzbox_ip}/login_sid.lua?username={self.fritzbox_user}&response={challenge}-{md5_hash}"
            response = requests.get(auth_url, timeout=5)
            sid = response.text.split("<SID>")[1].split("</SID>")[0]

            # Step 4: Validate and cache the SID
            if sid and sid != "0000000000000000":  # "0000000000000000" means auth failed
                self._cached_sid = sid
                self._sid_timestamp = current_time
                return sid
            else:
                print("ERROR: FritzBox authentication failed - check username/password")
                return None

        except Exception as e:
            print(f"ERROR: Could not authenticate with FritzBox: {e}")
            return None

    def collect_fritzbox_data_all(self):
        """
        Collect all FritzBox data (DOCSIS cable metrics + connection speeds).
        Runs sequentially to avoid overloading the FritzBox.
        """
        # Authenticate first
        sid = self.get_sid()
        if not sid or sid == "0000000000000000":
            print("ERROR: Cannot collect FritzBox data - authentication failed")
            return

        # ========================================
        # Part 1: Collect DOCSIS Cable Metrics
        # ========================================
        try:
            # Request DOCSIS data from FritzBox
            response = requests.post(
                f"http://{self.fritzbox_ip}/data.lua",
                data={
                    "xhr": 1,
                    "sid": sid,
                    "lang": "de",
                    "page": "docInfo",  # DOCSIS information page
                    "xhrId": "all",
                    "no_sidrenew": ""
                },
                timeout=10
            )
            docsis = response.json()

            # Auto-detect DOCSIS version (3.0 or 3.1)
            # Different versions have different channel counts and data structures
            docsis_version = 'docsis30'
            if docsis.get('data', {}).get('channelUs', {}).get(docsis_version) is None:
                docsis_version = 'docsis31'

            # --- Process Upstream Channels ---
            upstream_channels = docsis.get('data', {}).get('channelUs', {}).get(docsis_version, [])
            for channel in upstream_channels:
                channel_id = channel.get('channelID', 'unknown')

                # Power level in dBmV
                if 'powerLevel' in channel:
                    self.docsis_power_level_up.labels(channel_id=channel_id).set(float(channel['powerLevel']))

                # Frequency in Hz (clean up formatting from API)
                if 'frequency' in channel:
                    freq = channel['frequency'].replace(' Hz', '').replace('.', '').replace(',', '')
                    self.docsis_frequency_up.labels(channel_id=channel_id).set(float(freq))

                # Modulation (QAM value) - API field name varies by firmware
                modulation_field = channel.get('type') or channel.get('modulation') or channel.get('mod') or channel.get('qam')
                if modulation_field:
                    match = self._qam_pattern.search(str(modulation_field))  # Extract number from "256QAM"
                    if match:
                        self.docsis_modulation_up.labels(channel_id=channel_id).set(int(match.group(1)))
                    else:
                        print(f"Warning: Could not parse QAM for upstream channel {channel_id}: '{modulation_field}'")
                else:
                    print(f"Warning: No modulation field for upstream channel {channel_id}")

                # Multiplex method (ATDMA, SCDMA, TDMA)
                if 'multiplex' in channel:
                    multiplex = channel['multiplex']
                    multiplex_map = {'ATDMA': 1, 'SCDMA': 2, 'TDMA': 3}
                    multiplex_value = multiplex_map.get(multiplex, 0)
                    self.docsis_multiplex_up.labels(channel_id=channel_id, multiplex=multiplex).set(multiplex_value)

            # --- Process Downstream Channels ---
            downstream_channels = docsis.get('data', {}).get('channelDs', {}).get(docsis_version, [])
            for channel in downstream_channels:
                channel_id = channel.get('channelID', 'unknown')

                # Power level in dBmV
                if 'powerLevel' in channel:
                    self.docsis_power_level_down.labels(channel_id=channel_id).set(float(channel['powerLevel']))

                # Frequency in Hz
                if 'frequency' in channel:
                    freq = channel['frequency'].replace(' Hz', '').replace('.', '').replace(',', '')
                    self.docsis_frequency_down.labels(channel_id=channel_id).set(float(freq))

                # Modulation (QAM value)
                modulation_field = channel.get('type') or channel.get('modulation') or channel.get('mod') or channel.get('qam')
                if modulation_field:
                    match = self._qam_pattern.search(str(modulation_field))
                    if match:
                        self.docsis_modulation_down.labels(channel_id=channel_id).set(int(match.group(1)))
                    else:
                        print(f"Warning: Could not parse QAM for downstream channel {channel_id}: '{modulation_field}'")
                else:
                    print(f"Warning: No modulation field for downstream channel {channel_id}")

                # Signal-to-Noise Ratio in dB
                if 'mse' in channel:
                    self.docsis_snr_down.labels(channel_id=channel_id).set(float(channel['mse']))

                # Latency in milliseconds
                if 'latency' in channel:
                    self.docsis_latency_down.labels(channel_id=channel_id).set(float(channel['latency']))

                # Corrected Errors (calculate delta from cumulative counter)
                if 'corrErrors' in channel:
                    current = int(channel['corrErrors'])
                    previous = self._previous_corr_errors.get(channel_id, current)

                    # Only count new errors (handle FritzBox reboots gracefully)
                    if current >= previous:
                        delta = current - previous
                        if delta > 0:
                            self.docsis_corr_errors.labels(channel_id=channel_id).inc(delta)

                    self._previous_corr_errors[channel_id] = current

                # Uncorrected Errors (calculate delta from cumulative counter)
                if 'nonCorrErrors' in channel:
                    current = int(channel['nonCorrErrors'])
                    previous = self._previous_uncorr_errors.get(channel_id, current)

                    # Only count new errors
                    if current >= previous:
                        delta = current - previous
                        if delta > 0:
                            self.docsis_uncorr_errors.labels(channel_id=channel_id).inc(delta)

                    self._previous_uncorr_errors[channel_id] = current

        except Exception as e:
            print(f"ERROR: Could not collect DOCSIS data: {e}")

        # ========================================
        # Part 2: Collect Connection Speed
        # ========================================
        try:
            # Request all speed data from netMoni page (has both current and max)
            response = requests.post(
                f"http://{self.fritzbox_ip}/data.lua",
                data={
                    "xhr": 1,
                    "sid": sid,
                    "lang": "de",
                    "page": "netMoni",
                    "xhrId": "all",
                    "no_sidrenew": ""
                },
                timeout=10
            )
            data = response.json()

            # Extract speeds from sync_groups (all values in bytes/s, convert to bits/s)
            if 'data' in data and 'sync_groups' in data['data']:
                sync_groups = data['data']['sync_groups']
                if sync_groups and len(sync_groups) > 0:
                    sync_data = sync_groups[0]

                    # Current traffic speeds
                    if 'us_bps_curr_max' in sync_data:
                        self.connection_upload_speed_bps.set(float(sync_data['us_bps_curr_max']) * 8)
                    if 'ds_bps_curr_max' in sync_data:
                        self.connection_download_speed_bps.set(float(sync_data['ds_bps_curr_max']) * 8)

                    # Maximum line capacity
                    if 'us_bps_max' in sync_data:
                        self.connection_upload_max_bps.set(float(sync_data['us_bps_max']) * 8)
                    if 'ds_bps_max' in sync_data:
                        self.connection_download_max_bps.set(float(sync_data['ds_bps_max']) * 8)

        except Exception as e:
            print(f"ERROR: Could not collect connection speed: {e}")

    def collect_ping_data(self):
        """
        Collect ping statistics (latency and packet loss).
        """
        try:
            # Send 5 pings to target
            transmitter = PingTransmitter()
            transmitter.destination = self.ping_target
            transmitter.count = 5
            transmitter.timeout = 10
            result = transmitter.ping()

            # Parse results
            ping_parser = PingParsing()
            stats = ping_parser.parse(result).as_dict()

            # Store metrics
            if stats.get('rtt_avg') is not None:
                self.ping_rtt_avg.labels(target=self.ping_target).set(stats['rtt_avg'])
            if stats.get('rtt_min') is not None:
                self.ping_rtt_min.labels(target=self.ping_target).set(stats['rtt_min'])
            if stats.get('rtt_max') is not None:
                self.ping_rtt_max.labels(target=self.ping_target).set(stats['rtt_max'])
            if stats.get('packet_loss_rate') is not None:
                self.ping_packet_loss.labels(target=self.ping_target).set(stats['packet_loss_rate'])

        except Exception as e:
            print(f"ERROR: Could not collect ping data: {e}")

    def collect_homeassistant_data(self):
        """
        Collect data from Home Assistant (optional - only if configured).
        Currently collects outdoor temperature for correlation with cable quality.
        """
        # Skip if not configured
        if not self.homeassistant_url or not self.homeassistant_token:
            return

        try:
            # Request entity state from Home Assistant
            headers = {
                "Authorization": f"Bearer {self.homeassistant_token}",
                "Content-Type": "application/json"
            }
            url = f"{self.homeassistant_url}/api/states/{self.homeassistant_entity}"
            response = requests.get(url, headers=headers, timeout=10)

            # Extract temperature value
            if response.status_code == 200:
                data = response.json()
                state = data.get('state')
                if state and state not in ['unavailable', 'unknown']:
                    temperature = float(state)
                    self.outdoor_temperature.labels(entity_id=self.homeassistant_entity).set(temperature)
            else:
                print(f"ERROR: Home Assistant returned HTTP {response.status_code}")

        except Exception as e:
            print(f"ERROR: Could not collect Home Assistant data: {e}")

    def collect(self):
        """
        Main collection method called by Prometheus scraper.
        Runs three data collectors in parallel for efficiency:
        1. FritzBox data (DOCSIS + connection speed)
        2. Ping statistics
        3. Home Assistant data (optional)
        """
        # Authenticate once before starting parallel collection
        if self.fritzbox_password:
            self.get_sid()

        # Define collectors to run
        collectors = [
            self.collect_fritzbox_data_all,   # FritzBox cable modem metrics
            self.collect_ping_data,            # Network ping test
            self.collect_homeassistant_data    # Temperature (if configured)
        ]

        # Run all collectors in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(collector): collector.__name__ for collector in collectors}
            for future in as_completed(futures):
                collector_name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"ERROR in {collector_name}: {e}")

        return []  # Prometheus requires this


# ========================================
# Main Entry Point
# ========================================
if __name__ == '__main__':
    print("Starting FritzBox DOCSIS Monitoring Exporter...")
    print("Port: 8000")
    print("Metrics endpoint: http://localhost:8000/metrics")

    # Create and register collector with Prometheus
    collector = FritzboxCollector()
    REGISTRY.register(collector)

    # Start HTTP server for Prometheus to scrape
    start_http_server(8000)
    print("Exporter is running!")

    # Keep server alive
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nShutting down exporter...")