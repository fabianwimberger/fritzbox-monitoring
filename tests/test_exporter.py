"""Unit tests for DOCSIS parsing and per-channel processing in exporter.py."""

import pytest

from exporter import FritzboxCollector


def _value(metric, **labels) -> float:
    return metric.labels(**labels)._value.get()


class TestParseFrequency:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("36.000.000 Hz", 36_000_000),
            ("36,000,000", 36_000_000),
            ("36000000", 36_000_000),
            ("300 MHz", 300_000_000),
            ("1.2 GHz", 1_200_000_000),
            ("300 kHz", 300_000),
            ("36,5 MHz", 36_500_000),
            ("not a frequency", None),
            ("", None),
            (None, None),
        ],
    )
    def test_formats(self, collector: FritzboxCollector, raw, expected) -> None:
        assert collector._parse_frequency(raw) == expected


class TestUpstreamChannel:
    def test_sets_power_frequency_modulation_and_multiplex(
        self, collector: FritzboxCollector
    ) -> None:
        collector._process_upstream_channel(
            {
                "channelID": "up-test-1",
                "powerLevel": "45.2",
                "frequency": "36.000.000 Hz",
                "type": "QAM256",
                "multiplex": "ATDMA",
            }
        )
        assert _value(collector.docsis_power_level_up, channel_id="up-test-1") == 45.2
        assert (
            _value(collector.docsis_frequency_up, channel_id="up-test-1") == 36_000_000
        )
        assert _value(collector.docsis_modulation_up, channel_id="up-test-1") == 256
        assert (
            _value(
                collector.docsis_multiplex_up,
                channel_id="up-test-1",
                multiplex="ATDMA",
            )
            == 1
        )


class TestDownstreamChannel:
    def test_sets_downstream_fields(self, collector: FritzboxCollector) -> None:
        collector._process_downstream_channel(
            {
                "channelID": "down-test-1",
                "powerLevel": "3.5",
                "frequency": "114.000.000 Hz",
                "modulation": "QAM256",
                "mse": "39.5",
                "latency": "0.5",
            }
        )
        assert (
            _value(collector.docsis_power_level_down, channel_id="down-test-1") == 3.5
        )
        assert (
            _value(collector.docsis_frequency_down, channel_id="down-test-1")
            == 114_000_000
        )
        assert _value(collector.docsis_modulation_down, channel_id="down-test-1") == 256
        assert _value(collector.docsis_snr_down, channel_id="down-test-1") == 39.5
        assert _value(collector.docsis_latency_down, channel_id="down-test-1") == 0.5

    def test_corrected_errors_track_deltas(self, collector: FritzboxCollector) -> None:
        cid = "down-errors-1"
        collector._process_downstream_channel({"channelID": cid, "corrErrors": 10})
        # The first sample only establishes a baseline.
        assert _value(collector.docsis_corr_errors, channel_id=cid) == 0
        collector._process_downstream_channel({"channelID": cid, "corrErrors": 25})
        assert _value(collector.docsis_corr_errors, channel_id=cid) == 15
        # A counter reset (modem reboot) must not yield a negative or huge delta.
        collector._process_downstream_channel({"channelID": cid, "corrErrors": 3})
        assert _value(collector.docsis_corr_errors, channel_id=cid) == 18

    def test_prune_removes_stale_channel_state(
        self, collector: FritzboxCollector
    ) -> None:
        cid = "down-prune-1"
        collector._process_downstream_channel(
            {"channelID": cid, "corrErrors": 5, "nonCorrErrors": 2}
        )
        assert cid in collector._previous_corr_errors
        assert cid in collector._previous_uncorr_errors
        collector._prune_downstream_channels(set())
        assert cid not in collector._previous_corr_errors
        assert cid not in collector._previous_uncorr_errors
