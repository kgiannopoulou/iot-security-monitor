"""Controlled test scenarios: each one must trigger exactly its rules."""

import pytest
from scapy.layers.l2 import Ether

from generate_scenarios import SCENARIOS, build
from iotmon.capture import read_pcap
from iotmon.config import load_config
from iotmon.parser import parse_packet
from iotmon.pipeline import Monitor


def _records(scenario):
    out = []
    for pkt in build(scenario):
        wire = Ether(bytes(pkt))  # serialise and re-dissect, as if read from a capture
        wire.time = pkt.time
        out.append(parse_packet(wire))
    return out


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_scenario_triggers_exactly_its_rules(scenario):
    mon = Monitor(load_config())
    for r in _records(scenario):
        mon.process(r)
    mon.close()
    assert sorted({a.rule_id for a in mon.alerts}) == sorted(scenario.expect), \
        [(a.rule_id, a.title) for a in mon.alerts]


BENIGN = [s for s in SCENARIOS if s.benign]


@pytest.mark.parametrize("scenario", BENIGN, ids=[s.name for s in BENIGN])
def test_benign_look_alikes_are_never_high_confidence(scenario):
    """Legitimate events that resemble attacks: silent, or a false positive
    an analyst can see is doubtful (confidence below 'high')."""
    mon = Monitor(load_config())
    for r in _records(scenario):
        mon.process(r)
    mon.close()
    assert all(a.confidence < 0.75 for a in mon.alerts), [(a.rule_id, a.confidence) for a in mon.alerts]


def test_attacks_score_higher_confidence_than_benign_look_alikes():
    def confidences(scenarios):
        out = []
        for sc in scenarios:
            mon = Monitor(load_config())
            for r in _records(sc):
                mon.process(r)
            mon.close()
            out += [a.confidence for a in mon.alerts]
        return out

    attacks = confidences([s for s in SCENARIOS if s.expect and not s.benign])
    benign = confidences(BENIGN)
    assert benign and attacks
    assert sum(attacks) / len(attacks) > sum(benign) / len(benign)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_committed_scenario_matches_generator(scenario):
    on_disk = [r.info for r in read_pcap(str(scenario.path))]
    assert on_disk == [r.info for r in _records(scenario)]
