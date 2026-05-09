#!/usr/bin/env python
"""
FritzBox DOCSIS Cable Monitoring Exporter for Prometheus
"""

import json
import os
import re
import time
import hashlib
import logging
import requests
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode
from prometheus_client import start_http_server, Gauge, Counter, REGISTRY
from pingparsing import PingParsing, PingTransmitter
from fritzconnection import FritzConnection

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class FritzboxCollector:
    def __init__(self):
        self.fritzbox_ip = os.environ.get("FRITZBOX_IP", "192.168.178.1")
        self.fritzbox_user = os.environ.get("FRITZBOX_USER")
        self.fritzbox_password = os.environ.get("FRITZBOX_PASSWORD")
        self.ping_target = os.environ.get("PING_TARGET", "1.1.1.1")
        self.port = int(os.environ.get("PORT", "8000"))
        self.lan_host_interval_seconds = int(
            os.environ.get("LAN_HOST_INTERVAL_SECONDS", "180")
        )

        self._cached_sid = None
        self._http_session = requests.Session()
        self._fc: FritzConnection | None = None
        self._qam_pattern = re.compile(r"(\d+)")
        self._freq_pattern = re.compile(r"[\d.,]+")
        self._collect_lock = threading.Lock()
        self._last_lan_host_collection = 0.0

        self._executor = ThreadPoolExecutor(max_workers=2)

        # DOCSIS Upstream Metrics
        self.docsis_power_level_up = Gauge(
            "fritzbox_docsis_upstream_power_level_dbmv",
            "Upstream power level in dBmV",
            ["channel_id"],
        )
        self.docsis_frequency_up = Gauge(
            "fritzbox_docsis_upstream_frequency_hz",
            "Upstream frequency in Hz",
            ["channel_id"],
        )
        self.docsis_modulation_up = Gauge(
            "fritzbox_docsis_upstream_modulation_qam",
            "Upstream modulation (QAM)",
            ["channel_id"],
        )
        self.docsis_multiplex_up = Gauge(
            "fritzbox_docsis_upstream_multiplex_info",
            "Upstream multiplex method",
            ["channel_id", "multiplex"],
        )

        # DOCSIS Downstream Metrics
        self.docsis_power_level_down = Gauge(
            "fritzbox_docsis_downstream_power_level_dbmv",
            "Downstream power level in dBmV",
            ["channel_id"],
        )
        self.docsis_frequency_down = Gauge(
            "fritzbox_docsis_downstream_frequency_hz",
            "Downstream frequency in Hz",
            ["channel_id"],
        )
        self.docsis_modulation_down = Gauge(
            "fritzbox_docsis_downstream_modulation_qam",
            "Downstream modulation (QAM)",
            ["channel_id"],
        )
        self.docsis_snr_down = Gauge(
            "fritzbox_docsis_downstream_snr_db", "Downstream SNR in dB", ["channel_id"]
        )
        self.docsis_latency_down = Gauge(
            "fritzbox_docsis_downstream_latency_ms",
            "Downstream latency in ms",
            ["channel_id"],
        )
        # Keep Counter for errors to track increments over time
        self.docsis_corr_errors = Counter(
            "fritzbox_docsis_downstream_corrected_errors_total",
            "Downstream corrected errors",
            ["channel_id"],
        )
        self.docsis_uncorr_errors = Counter(
            "fritzbox_docsis_downstream_uncorrected_errors_total",
            "Downstream uncorrected errors",
            ["channel_id"],
        )

        self._state_file = os.environ.get(
            "STATE_FILE", "/app/data/fritzbox_exporter_state.json"
        )
        self._previous_corr_errors = self._load_state("corr_errors", {})
        self._previous_uncorr_errors = self._load_state("uncorr_errors", {})

        self.up = Gauge(
            "fritzbox_up",
            "Whether the last FritzBox DOCSIS scrape succeeded",
        )
        self.scrape_duration_seconds = Gauge(
            "fritzbox_scrape_duration_seconds",
            "Duration of the last FritzBox scrape in seconds",
        )

        # Connection Speed Metrics
        self.connection_upload_speed_bps = Gauge(
            "fritzbox_connection_upload_speed_bps", "Current upload speed in bps"
        )
        self.connection_download_speed_bps = Gauge(
            "fritzbox_connection_download_speed_bps", "Current download speed in bps"
        )
        self.connection_upload_max_bps = Gauge(
            "fritzbox_connection_upload_max_bps", "Maximum upload speed in bps"
        )
        self.connection_download_max_bps = Gauge(
            "fritzbox_connection_download_max_bps", "Maximum download speed in bps"
        )

        # Ping Metrics
        self.ping_rtt_avg = Gauge(
            "fritzbox_ping_rtt_avg_ms", "Ping avg RTT in ms", ["target"]
        )
        self.ping_rtt_min = Gauge(
            "fritzbox_ping_rtt_min_ms", "Ping min RTT in ms", ["target"]
        )
        self.ping_rtt_max = Gauge(
            "fritzbox_ping_rtt_max_ms", "Ping max RTT in ms", ["target"]
        )

        # LAN Host metric — enables MAC -> name/IP joins in other dashboards
        self.lan_host = Gauge(
            "fritzbox_lan_host",
            "Known LAN host active state",
            ["mac"],
        )

    def get_sid(self, force_refresh=False):
        """Authenticate with FritzBox and get Session ID. Cached until invalid."""
        if not force_refresh and self._cached_sid:
            return self._cached_sid

        try:
            response = self._http_session.get(
                f"http://{self.fritzbox_ip}/login_sid.lua", timeout=5
            )
            root = ET.fromstring(response.text)
            challenge = root.findtext("Challenge", "")
            if not challenge:
                logger.error("No challenge in FritzBox login response")
                return None

            challenge_response = f"{challenge}-{self.fritzbox_password}"
            md5_hash = hashlib.md5(challenge_response.encode("utf-16le")).hexdigest()

            params = {
                "username": self.fritzbox_user or "",
                "response": f"{challenge}-{md5_hash}",
            }
            auth_url = f"http://{self.fritzbox_ip}/login_sid.lua?{urlencode(params)}"
            response = self._http_session.get(auth_url, timeout=5)
            root = ET.fromstring(response.text)
            sid = root.findtext("SID", "")

            if sid and sid != "0000000000000000":
                self._cached_sid = sid
                return sid
            else:
                logger.error("FritzBox authentication failed")
                return None
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return None

    def _call_data_lua(self, sid, page, xhrid="all", retry_on_auth_fail=True):
        """Call data.lua endpoint and return JSON response. Refreshes auth on 403/invalid session."""
        try:
            response = self._http_session.post(
                f"http://{self.fritzbox_ip}/data.lua",
                data={"xhr": 1, "sid": sid, "page": page, "xhrId": xhrid},
                timeout=10,
            )
            result = response.json()

            # Detect auth failure (FritzBox returns error in JSON for invalid sessions)
            if (
                isinstance(result, dict) and result.get("error")
            ) or response.status_code == 403:
                if retry_on_auth_fail:
                    logger.info("Session expired, re-authenticating...")
                    new_sid = self.get_sid(force_refresh=True)
                    if new_sid:
                        return self._call_data_lua(
                            new_sid, page, xhrid, retry_on_auth_fail=False
                        )
                return None

            return result
        except Exception as e:
            logger.error(f"data.lua?page={page} failed: {e}")
            return None

    def collect_fritzbox_data_all(self):
        """Collect DOCSIS cable metrics and connection speeds."""
        timings = []
        auth_start = time.time()
        sid = self.get_sid()
        if not sid or sid == "0000000000000000":
            logger.error("Authentication failed")
            return
        timings.append(f"auth={(time.time() - auth_start) * 1000:.0f}ms")

        try:
            docsis_start = time.time()
            docsis = self._call_data_lua(sid, "docInfo")
            timings.append(f"docsis={(time.time() - docsis_start) * 1000:.0f}ms")
            if not docsis:
                self.up.set(0)
                return timings

            docsis_version = "docsis30"
            if not docsis.get("data", {}).get("channelUs", {}).get(docsis_version):
                docsis_version = "docsis31"

            # Clear previous channel metrics to handle channel changes/reboots
            self.docsis_power_level_up.clear()
            self.docsis_frequency_up.clear()
            self.docsis_modulation_up.clear()
            self.docsis_multiplex_up.clear()
            self.docsis_power_level_down.clear()
            self.docsis_frequency_down.clear()
            self.docsis_modulation_down.clear()
            self.docsis_snr_down.clear()
            self.docsis_latency_down.clear()

            upstream_channels = (
                docsis.get("data", {}).get("channelUs", {}).get(docsis_version, [])
            )
            for channel in upstream_channels:
                try:
                    self._process_upstream_channel(channel)
                except Exception as e:
                    channel_id = channel.get("channelID", "unknown")
                    logger.warning(f"Skipping upstream channel {channel_id}: {e}")

            downstream_channels = (
                docsis.get("data", {}).get("channelDs", {}).get(docsis_version, [])
            )
            current_downstream_channel_ids = set()
            for channel in downstream_channels:
                try:
                    current_downstream_channel_ids.add(
                        str(channel.get("channelID", "unknown"))
                    )
                    self._process_downstream_channel(channel)
                except Exception as e:
                    channel_id = channel.get("channelID", "unknown")
                    logger.warning(f"Skipping downstream channel {channel_id}: {e}")
            self._prune_downstream_channels(current_downstream_channel_ids)
            self.up.set(1)

        except Exception as e:
            logger.error(f"DOCSIS collection failed: {e}")
            self.up.set(0)

        speed_timings = self.collect_connection_speeds()
        if speed_timings:
            timings.append(speed_timings)
        return timings

    def _process_upstream_channel(self, channel: dict) -> None:
        """Process a single upstream channel."""
        channel_id = str(channel.get("channelID", "unknown"))
        if "powerLevel" in channel:
            self.docsis_power_level_up.labels(channel_id=channel_id).set(
                float(channel["powerLevel"])
            )
        if "frequency" in channel:
            freq = self._parse_frequency(channel["frequency"])
            if freq is not None:
                self.docsis_frequency_up.labels(channel_id=channel_id).set(freq)

        modulation_field = (
            channel.get("type")
            or channel.get("modulation")
            or channel.get("mod")
            or channel.get("qam")
        )
        if modulation_field:
            match = self._qam_pattern.search(str(modulation_field))
            if match:
                self.docsis_modulation_up.labels(channel_id=channel_id).set(
                    int(match.group(1))
                )

        if "multiplex" in channel:
            multiplex_map = {"ATDMA": 1, "SCDMA": 2, "TDMA": 3}
            self.docsis_multiplex_up.labels(
                channel_id=channel_id, multiplex=channel["multiplex"]
            ).set(multiplex_map.get(channel["multiplex"], 0))

    def _process_downstream_channel(self, channel: dict) -> None:
        """Process a single downstream channel."""
        channel_id = str(channel.get("channelID", "unknown"))
        if "powerLevel" in channel:
            self.docsis_power_level_down.labels(channel_id=channel_id).set(
                float(channel["powerLevel"])
            )
        if "frequency" in channel:
            freq = self._parse_frequency(channel["frequency"])
            if freq is not None:
                self.docsis_frequency_down.labels(channel_id=channel_id).set(freq)

        modulation_field = (
            channel.get("type")
            or channel.get("modulation")
            or channel.get("mod")
            or channel.get("qam")
        )
        if modulation_field:
            match = self._qam_pattern.search(str(modulation_field))
            if match:
                self.docsis_modulation_down.labels(channel_id=channel_id).set(
                    int(match.group(1))
                )

        if "mse" in channel:
            self.docsis_snr_down.labels(channel_id=channel_id).set(
                float(channel["mse"])
            )
        if "latency" in channel:
            self.docsis_latency_down.labels(channel_id=channel_id).set(
                float(channel["latency"])
            )

        if "corrErrors" in channel:
            current = int(channel["corrErrors"])
            previous = self._previous_corr_errors.get(channel_id, current)
            delta = current - previous if current >= previous else current
            if delta > 0:
                self.docsis_corr_errors.labels(channel_id=channel_id).inc(delta)
            self._previous_corr_errors[channel_id] = current

        if "nonCorrErrors" in channel:
            current = int(channel["nonCorrErrors"])
            previous = self._previous_uncorr_errors.get(channel_id, current)
            delta = current - previous if current >= previous else current
            if delta > 0:
                self.docsis_uncorr_errors.labels(channel_id=channel_id).inc(delta)
            self._previous_uncorr_errors[channel_id] = current

    def _prune_downstream_channels(self, current_channel_ids: set[str]) -> None:
        stale_corr = set(self._previous_corr_errors) - current_channel_ids
        stale_uncorr = set(self._previous_uncorr_errors) - current_channel_ids
        for channel_id in stale_corr:
            self._previous_corr_errors.pop(channel_id, None)
            self._remove_metric_label(self.docsis_corr_errors, channel_id)
        for channel_id in stale_uncorr:
            self._previous_uncorr_errors.pop(channel_id, None)
            self._remove_metric_label(self.docsis_uncorr_errors, channel_id)

    @staticmethod
    def _remove_metric_label(metric, *label_values) -> None:
        try:
            metric.remove(*label_values)
        except (AttributeError, KeyError):
            return

    def _get_fritz_connection(self) -> FritzConnection:
        """Return a FritzConnection, creating it lazily if needed."""
        if self._fc is None:
            self._fc = FritzConnection(
                address=self.fritzbox_ip,
                user=self.fritzbox_user,
                password=self.fritzbox_password,
                timeout=10.0,
                use_cache=True,
            )
        return self._fc

    def collect_connection_speeds(self):
        """Collect connection speeds via TR-064 API."""
        try:
            speed_start = time.time()
            fc = self._get_fritz_connection()
            addon_info = fc.call_action("WANCommonIFC1", "GetAddonInfos")

            if "NewByteSendRate" in addon_info:
                us_current = float(addon_info["NewByteSendRate"]) * 8
                self.connection_upload_speed_bps.set(us_current)

            if "NewByteReceiveRate" in addon_info:
                ds_current = float(addon_info["NewByteReceiveRate"]) * 8
                self.connection_download_speed_bps.set(ds_current)

            link_props = fc.call_action(
                "WANCommonInterfaceConfig1", "GetCommonLinkProperties"
            )

            if "NewLayer1UpstreamMaxBitRate" in link_props:
                self.connection_upload_max_bps.set(
                    float(link_props["NewLayer1UpstreamMaxBitRate"])
                )

            if "NewLayer1DownstreamMaxBitRate" in link_props:
                self.connection_download_max_bps.set(
                    float(link_props["NewLayer1DownstreamMaxBitRate"])
                )

            return f"speed={(time.time() - speed_start) * 1000:.0f}ms"

        except Exception as e:
            logger.error(f"Speed collection failed: {e}")
            return None

    def collect_ping_data(self):
        """Collect ping statistics."""
        try:
            ping_start = time.time()
            transmitter = PingTransmitter()
            transmitter.destination = self.ping_target
            transmitter.count = 5
            transmitter.deadline = 2
            # Note: Removed -i 0.2 option as it requires root privileges on many systems
            result = transmitter.ping()

            timing = f"ping={(time.time() - ping_start) * 1000:.0f}ms"

            stats = PingParsing().parse(result).as_dict()
            if stats.get("rtt_avg") is not None:
                self.ping_rtt_avg.labels(target=self.ping_target).set(stats["rtt_avg"])
            if stats.get("rtt_min") is not None:
                self.ping_rtt_min.labels(target=self.ping_target).set(stats["rtt_min"])
            if stats.get("rtt_max") is not None:
                self.ping_rtt_max.labels(target=self.ping_target).set(stats["rtt_max"])

            return timing

        except Exception as e:
            logger.error(f"Ping collection failed: {e}")
            return None

    def collect_lan_hosts(self):
        try:
            hosts = {}
            fc = self._get_fritz_connection()
            try:
                path = fc.call_action("Hosts1", "X_AVM-DE_GetHostListPath")[
                    "NewX_AVM-DE_HostListPath"
                ]
                response = self._http_session.get(
                    f"http://{self.fritzbox_ip}:49000{path}", timeout=10
                )
                response.raise_for_status()
                root = ET.fromstring(response.text)
                for item in root.findall("Item"):
                    mac = (item.findtext("MACAddress") or "").upper().strip()
                    if not mac:
                        continue
                    hosts[mac] = {
                        "ip": item.findtext("IPAddress") or "",
                        "name": item.findtext("HostName") or "",
                        "interface": item.findtext("InterfaceType") or "",
                        "active": str(int((item.findtext("Active") or "0") == "1")),
                    }
            except Exception:
                count_result = fc.call_action("Hosts1", "GetHostNumberOfEntries")
                count = int(count_result.get("NewHostNumberOfEntries", 0))
                for i in range(count):
                    try:
                        entry = fc.call_action(
                            "Hosts1", "GetGenericHostEntry", NewIndex=i
                        )
                        mac = (entry.get("NewMACAddress") or "").upper().strip()
                        if not mac:
                            continue
                        hosts[mac] = {
                            "ip": entry.get("NewIPAddress") or "",
                            "name": entry.get("NewHostName") or "",
                            "interface": entry.get("NewInterfaceType") or "",
                            "active": str(int(bool(entry.get("NewActive")))),
                        }
                    except Exception:
                        continue

            self.lan_host.clear()
            for mac, h in hosts.items():
                self.lan_host.labels(mac=mac).set(float(h["active"]))

            logger.info("LAN host collection: %d hosts", len(hosts))
        except Exception as e:
            logger.warning("LAN host collection failed: %s", e)

    def collect(self):
        """Main collection method called by Prometheus scraper."""
        if not self._collect_lock.acquire(blocking=False):
            logger.warning("Skipping overlapping scrape")
            return []

        total_start = time.time()
        timings = []

        try:
            collectors = [self.collect_fritzbox_data_all, self.collect_ping_data]

            futures = {
                self._executor.submit(collector): collector for collector in collectors
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if isinstance(result, list):
                        timings.extend(result)
                    elif result:
                        timings.append(result)
                except Exception as e:
                    logger.error(f"Collection error: {e}")

            total_time = time.time() - total_start
            self.scrape_duration_seconds.set(total_time)
            timings_str = ", ".join(timings) if timings else "no data"
            logger.info(f"[{total_time * 1000:.0f}ms] {timings_str}")

            self._save_state()

            if (
                time.monotonic() - self._last_lan_host_collection
                >= self.lan_host_interval_seconds
            ):
                try:
                    self.collect_lan_hosts()
                    self._last_lan_host_collection = time.monotonic()
                except Exception as e:
                    logger.warning(f"LAN host collection failed: {e}")

            return []
        finally:
            self._collect_lock.release()

    def _load_state(self, key, default):
        """Load persisted state from file."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, "r") as f:
                    data = json.load(f)
                    return data.get(key, default)
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")
        return default

    def _save_state(self):
        """Persist state to file."""
        try:
            dirname = os.path.dirname(self._state_file)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            data = {
                "corr_errors": self._previous_corr_errors,
                "uncorr_errors": self._previous_uncorr_errors,
            }
            with open(self._state_file, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.warning("Failed to save state: %s", e)

    def _parse_frequency(self, freq_str):
        """Parse frequency string robustly, handling various formats.

        Handles formats like:
        - "36.000.000 Hz" (German with dots)
        - "36,000,000" (US format with commas)
        - "36000000"
        Returns frequency as integer (Hz) or None if parsing fails.
        """
        try:
            match = self._freq_pattern.search(str(freq_str))
            if not match:
                return None

            num_str = match.group(0)
            unit = str(freq_str).lower()
            multiplier = 1
            if "ghz" in unit:
                multiplier = 1_000_000_000
            elif "mhz" in unit:
                multiplier = 1_000_000
            elif "khz" in unit:
                multiplier = 1_000

            separators = [char for char in num_str if char in ".,"]
            if len(separators) > 1:
                value = float(num_str.replace(".", "").replace(",", ""))
                if multiplier > 1 and value >= multiplier:
                    multiplier = 1
            elif separators and multiplier > 1:
                value = float(num_str.replace(",", "."))
            else:
                value = float(num_str.replace(".", "").replace(",", ""))

            return int(value * multiplier)
        except (ValueError, AttributeError) as e:
            logger.warning(f"Failed to parse frequency '{freq_str}': {e}")
            return None


if __name__ == "__main__":
    collector = FritzboxCollector()
    REGISTRY.register(collector)
    start_http_server(collector.port)
    logger.info("FritzBox exporter started on port %d", collector.port)

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        collector._save_state()
        collector._executor.shutdown(wait=True)
        logger.info("Shutdown complete")
