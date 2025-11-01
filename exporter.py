#!/usr/bin/env python
"""
FritzBox DOCSIS Cable Monitoring Exporter for Prometheus
"""

import os
import re
import time
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from prometheus_client import start_http_server, Gauge, Counter, REGISTRY
from pingparsing import PingParsing, PingTransmitter
from fritzconnection import FritzConnection


class FritzboxCollector:
    def __init__(self):
        self.fritzbox_ip = os.environ.get("FRITZBOX_IP", "192.168.178.1")
        self.fritzbox_user = os.environ.get("FRITZBOX_USER")
        self.fritzbox_password = os.environ.get("FRITZBOX_PASSWORD")
        self.ping_target = os.environ.get("PING_TARGET", "1.1.1.1")

        self._cached_sid = None
        self._sid_timestamp = 0
        self._http_session = requests.Session()
        self._fc = FritzConnection(
            address=self.fritzbox_ip,
            user=self.fritzbox_user,
            password=self.fritzbox_password,
            timeout=10.0,
            use_cache=True
        )
        self._qam_pattern = re.compile(r'(\d+)')
        self._previous_corr_errors = {}
        self._previous_uncorr_errors = {}

        # DOCSIS Upstream Metrics
        self.docsis_power_level_up = Gauge('fritzbox_docsis_upstream_power_level_dbmv', 'Upstream power level in dBmV', ['channel_id'])
        self.docsis_frequency_up = Gauge('fritzbox_docsis_upstream_frequency_hz', 'Upstream frequency in Hz', ['channel_id'])
        self.docsis_modulation_up = Gauge('fritzbox_docsis_upstream_modulation_qam', 'Upstream modulation (QAM)', ['channel_id'])
        self.docsis_multiplex_up = Gauge('fritzbox_docsis_upstream_multiplex_info', 'Upstream multiplex method', ['channel_id', 'multiplex'])

        # DOCSIS Downstream Metrics
        self.docsis_power_level_down = Gauge('fritzbox_docsis_downstream_power_level_dbmv', 'Downstream power level in dBmV', ['channel_id'])
        self.docsis_frequency_down = Gauge('fritzbox_docsis_downstream_frequency_hz', 'Downstream frequency in Hz', ['channel_id'])
        self.docsis_modulation_down = Gauge('fritzbox_docsis_downstream_modulation_qam', 'Downstream modulation (QAM)', ['channel_id'])
        self.docsis_snr_down = Gauge('fritzbox_docsis_downstream_snr_db', 'Downstream SNR in dB', ['channel_id'])
        self.docsis_latency_down = Gauge('fritzbox_docsis_downstream_latency_ms', 'Downstream latency in ms', ['channel_id'])
        self.docsis_corr_errors = Counter('fritzbox_docsis_downstream_corrected_errors_total', 'Downstream corrected errors', ['channel_id'])
        self.docsis_uncorr_errors = Counter('fritzbox_docsis_downstream_uncorrected_errors_total', 'Downstream uncorrected errors', ['channel_id'])

        # Connection Speed Metrics
        self.connection_upload_speed_bps = Gauge('fritzbox_connection_upload_speed_bps', 'Current upload speed in bps')
        self.connection_download_speed_bps = Gauge('fritzbox_connection_download_speed_bps', 'Current download speed in bps')
        self.connection_upload_max_bps = Gauge('fritzbox_connection_upload_max_bps', 'Maximum upload speed in bps')
        self.connection_download_max_bps = Gauge('fritzbox_connection_download_max_bps', 'Maximum download speed in bps')

        # Ping Metrics
        self.ping_rtt_avg = Gauge('fritzbox_ping_rtt_avg_ms', 'Ping avg RTT in ms', ['target'])
        self.ping_rtt_min = Gauge('fritzbox_ping_rtt_min_ms', 'Ping min RTT in ms', ['target'])
        self.ping_rtt_max = Gauge('fritzbox_ping_rtt_max_ms', 'Ping max RTT in ms', ['target'])

    def get_sid(self, force_refresh=False):
        """Authenticate with FritzBox and get Session ID. Cached for 5 minutes."""
        current_time = time.time()

        if not force_refresh and self._cached_sid and (current_time - self._sid_timestamp) < 300:
            return self._cached_sid

        try:
            response = self._http_session.get(f"http://{self.fritzbox_ip}/login_sid.lua", timeout=5)
            challenge = response.text.split("<Challenge>")[1].split("</Challenge>")[0]

            challenge_response = f"{challenge}-{self.fritzbox_password}"
            md5_hash = hashlib.md5(challenge_response.encode('utf-16le')).hexdigest()

            auth_url = f"http://{self.fritzbox_ip}/login_sid.lua?username={self.fritzbox_user}&response={challenge}-{md5_hash}"
            response = self._http_session.get(auth_url, timeout=5)
            sid = response.text.split("<SID>")[1].split("</SID>")[0]

            if sid and sid != "0000000000000000":
                self._cached_sid = sid
                self._sid_timestamp = current_time
                return sid
            else:
                print("ERROR: FritzBox authentication failed")
                return None
        except Exception as e:
            print(f"ERROR: Authentication failed: {e}")
            return None

    def _call_data_lua(self, sid, page, xhrid="all"):
        """Call data.lua endpoint and return JSON response."""
        try:
            response = self._http_session.post(
                f"http://{self.fritzbox_ip}/data.lua",
                data={"xhr": 1, "sid": sid, "page": page, "xhrId": xhrid},
                timeout=10
            )
            return response.json()
        except Exception as e:
            print(f"ERROR: data.lua?page={page} failed: {e}")
            return None

    def collect_fritzbox_data_all(self):
        """Collect DOCSIS cable metrics and connection speeds."""
        auth_start = time.time()
        sid = self.get_sid()
        if not sid or sid == "0000000000000000":
            print("ERROR: Authentication failed")
            return
        print(f"[TIMING] Authentication: {(time.time() - auth_start)*1000:.0f}ms")

        try:
            docsis_start = time.time()
            docsis = self._call_data_lua(sid, "docInfo")
            print(f"[TIMING] DOCSIS collection: {(time.time() - docsis_start)*1000:.0f}ms")
            if not docsis:
                return

            docsis_version = 'docsis30'
            if not docsis.get('data', {}).get('channelUs', {}).get(docsis_version):
                docsis_version = 'docsis31'

            upstream_channels = docsis.get('data', {}).get('channelUs', {}).get(docsis_version, [])
            for channel in upstream_channels:
                channel_id = channel.get('channelID', 'unknown')
                if 'powerLevel' in channel:
                    self.docsis_power_level_up.labels(channel_id=channel_id).set(float(channel['powerLevel']))
                if 'frequency' in channel:
                    freq = channel['frequency'].replace(' Hz', '').replace('.', '').replace(',', '')
                    self.docsis_frequency_up.labels(channel_id=channel_id).set(float(freq))

                modulation_field = channel.get('type') or channel.get('modulation') or channel.get('mod') or channel.get('qam')
                if modulation_field:
                    match = self._qam_pattern.search(str(modulation_field))
                    if match:
                        self.docsis_modulation_up.labels(channel_id=channel_id).set(int(match.group(1)))

                if 'multiplex' in channel:
                    multiplex_map = {'ATDMA': 1, 'SCDMA': 2, 'TDMA': 3}
                    self.docsis_multiplex_up.labels(channel_id=channel_id, multiplex=channel['multiplex']).set(multiplex_map.get(channel['multiplex'], 0))

            downstream_channels = docsis.get('data', {}).get('channelDs', {}).get(docsis_version, [])
            for channel in downstream_channels:
                channel_id = channel.get('channelID', 'unknown')
                if 'powerLevel' in channel:
                    self.docsis_power_level_down.labels(channel_id=channel_id).set(float(channel['powerLevel']))
                if 'frequency' in channel:
                    freq = channel['frequency'].replace(' Hz', '').replace('.', '').replace(',', '')
                    self.docsis_frequency_down.labels(channel_id=channel_id).set(float(freq))

                modulation_field = channel.get('type') or channel.get('modulation') or channel.get('mod') or channel.get('qam')
                if modulation_field:
                    match = self._qam_pattern.search(str(modulation_field))
                    if match:
                        self.docsis_modulation_down.labels(channel_id=channel_id).set(int(match.group(1)))

                if 'mse' in channel:
                    self.docsis_snr_down.labels(channel_id=channel_id).set(float(channel['mse']))
                if 'latency' in channel:
                    self.docsis_latency_down.labels(channel_id=channel_id).set(float(channel['latency']))

                if 'corrErrors' in channel:
                    current = int(channel['corrErrors'])
                    previous = self._previous_corr_errors.get(channel_id, current)
                    if current >= previous and (delta := current - previous) > 0:
                        self.docsis_corr_errors.labels(channel_id=channel_id).inc(delta)
                    self._previous_corr_errors[channel_id] = current

                if 'nonCorrErrors' in channel:
                    current = int(channel['nonCorrErrors'])
                    previous = self._previous_uncorr_errors.get(channel_id, current)
                    if current >= previous and (delta := current - previous) > 0:
                        self.docsis_uncorr_errors.labels(channel_id=channel_id).inc(delta)
                    self._previous_uncorr_errors[channel_id] = current

        except Exception as e:
            print(f"ERROR: DOCSIS collection failed: {e}")

        self.collect_connection_speeds()

    def collect_connection_speeds(self):
        """Collect connection speeds via TR-064 API."""
        try:
            speed_start = time.time()
            addon_info = self._fc.call_action('WANCommonIFC1', 'GetAddonInfos')

            if 'NewByteSendRate' in addon_info:
                us_current = float(addon_info['NewByteSendRate']) * 8
                self.connection_upload_speed_bps.set(us_current)
                print(f"[DEBUG] Upload: {us_current/1e6:.2f} Mbps ({addon_info['NewByteSendRate']/1e6:.2f} MB/s)")

            if 'NewByteReceiveRate' in addon_info:
                ds_current = float(addon_info['NewByteReceiveRate']) * 8
                self.connection_download_speed_bps.set(ds_current)
                print(f"[DEBUG] Download: {ds_current/1e6:.2f} Mbps ({addon_info['NewByteReceiveRate']/1e6:.2f} MB/s)")

            link_props = self._fc.call_action('WANCommonInterfaceConfig1', 'GetCommonLinkProperties')

            if 'NewLayer1UpstreamMaxBitRate' in link_props:
                self.connection_upload_max_bps.set(float(link_props['NewLayer1UpstreamMaxBitRate']))

            if 'NewLayer1DownstreamMaxBitRate' in link_props:
                self.connection_download_max_bps.set(float(link_props['NewLayer1DownstreamMaxBitRate']))

            print(f"[TIMING] Speed collection: {(time.time() - speed_start)*1000:.0f}ms")

        except Exception as e:
            print(f"ERROR: Speed collection failed: {e}")

    def collect_ping_data(self):
        """Collect ping statistics."""
        try:
            ping_start = time.time()
            transmitter = PingTransmitter()
            transmitter.destination = self.ping_target
            transmitter.count = 5
            transmitter.deadline = 2
            transmitter.ping_option = "-i 0.2"
            result = transmitter.ping()

            print(f"[TIMING] Ping collection: {(time.time() - ping_start)*1000:.0f}ms")

            stats = PingParsing().parse(result).as_dict()
            if stats.get('rtt_avg') is not None:
                self.ping_rtt_avg.labels(target=self.ping_target).set(stats['rtt_avg'])
            if stats.get('rtt_min') is not None:
                self.ping_rtt_min.labels(target=self.ping_target).set(stats['rtt_min'])
            if stats.get('rtt_max') is not None:
                self.ping_rtt_max.labels(target=self.ping_target).set(stats['rtt_max'])

        except Exception as e:
            print(f"ERROR: Ping collection failed: {e}")

    def collect(self):
        """Main collection method called by Prometheus scraper."""
        total_start = time.time()
        print("\n=== Collection started ===")

        if self.fritzbox_password:
            self.get_sid()

        collectors = [self.collect_fritzbox_data_all, self.collect_ping_data]

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {executor.submit(collector): collector.__name__ for collector in collectors}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"ERROR: {e}")

        print(f"[TIMING] TOTAL: {(time.time() - total_start)*1000:.0f}ms\n")
        return []


if __name__ == '__main__':
    print("FritzBox DOCSIS Exporter")
    print("Port: 8000")

    collector = FritzboxCollector()
    REGISTRY.register(collector)
    start_http_server(8000)
    print("Running!\n")

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nShutting down...")
