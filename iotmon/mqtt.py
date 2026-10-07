"""MQTT visibility: who talks to the broker, and what they publish.

MQTT is the publish/subscribe protocol most IoT sensors use. A client opens
one TCP session to the broker, sends CONNECT (with a client ID), then
PUBLISHes messages to topics such as `factory/temperature`. Other clients
SUBSCRIBE to topics and the broker delivers matching messages to them.

The tracker turns parsed MQTT packets into broker-level events and keeps:

    clients  per client ID: host, username, broker, connects, refusals,
             messages published per topic, subscriptions
    topics   per topic: publishers, message count, last value

A session that was already open when the monitor started never shows its
CONNECT, so its client ID is unknown; it is tracked as `<ip> (no CONNECT
seen)` until the client reconnects.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import PacketRecord

MQTT_PORTS = {1883, 8883}


@dataclass(slots=True)
class MqttEvent:
    kind: str  # connect | connack | publish | subscribe
    client: str  # client key (client ID, or "<ip> (no CONNECT seen)")
    ip: str
    broker: str
    topic: str = ""
    value: str = ""
    retcode: int | None = None


@dataclass(slots=True)
class MqttClient:
    key: str
    client_id: str
    ip: str
    broker: str
    first_seen: float
    last_seen: float
    username: str = ""
    connects: int = 0
    refused: int = 0
    published: dict = field(default_factory=dict)  # topic -> messages
    subscriptions: set = field(default_factory=set)

    def as_dict(self) -> dict:
        return {"key": self.key, "client_id": self.client_id, "ip": self.ip, "broker": self.broker,
                "username": self.username, "first_seen": self.first_seen, "last_seen": self.last_seen,
                "connects": self.connects, "refused": self.refused,
                "messages": sum(self.published.values()),
                "topics": ",".join(sorted(self.published)), "subscriptions": ",".join(sorted(self.subscriptions))}


@dataclass(slots=True)
class MqttTopic:
    topic: str
    first_seen: float
    last_seen: float
    messages: int = 0
    last_value: str = ""
    publishers: set = field(default_factory=set)  # client keys

    def as_dict(self) -> dict:
        return {"topic": self.topic, "first_seen": self.first_seen, "last_seen": self.last_seen,
                "messages": self.messages, "last_value": self.last_value,
                "publishers": ",".join(sorted(self.publishers))}


class MqttTracker:
    def __init__(self):
        self.sessions: dict[tuple, str] = {}  # (client_ip, client_port, broker_ip) -> client ID
        self.clients: dict[str, MqttClient] = {}
        self.topics: dict[str, MqttTopic] = {}
        self.events: list[MqttEvent] = []  # produced by the last update()

    def update(self, rec: PacketRecord) -> list[MqttEvent]:
        self.events = []
        types = rec.meta.get("mqtt_types")
        if not types or rec.protocol != "TCP":
            return self.events
        from_broker = rec.sport in MQTT_PORTS and rec.dport not in MQTT_PORTS
        if from_broker:
            ip, port, broker = rec.dst_ip, rec.dport, rec.src_ip
        else:
            ip, port, broker = rec.src_ip, rec.sport, rec.dst_ip
        session = (ip, port, broker)

        if "CONNECT" in types and not from_broker:
            self.sessions[session] = rec.meta.get("mqtt_client_id") or f"{ip}:{port} (empty client ID)"
        key = self.sessions.get(session) or f"{ip} (no CONNECT seen)"
        client = self._client(key, ip, broker, rec.ts)

        if "CONNECT" in types and not from_broker:
            client.connects += 1
            client.username = rec.meta.get("mqtt_username", "")
            self.events.append(MqttEvent("connect", key, ip, broker))
        if "CONNACK" in types and from_broker:
            code = rec.meta.get("mqtt_retcode", 0)
            if code:
                client.refused += 1
            self.events.append(MqttEvent("connack", key, ip, broker, retcode=code))
        if not from_broker:
            for msg in rec.meta.get("mqtt_messages", []):
                topic = msg["topic"]
                client.published[topic] = client.published.get(topic, 0) + 1
                t = self.topics.get(topic)
                if t is None:
                    t = self.topics[topic] = MqttTopic(topic, rec.ts, rec.ts)
                t.last_seen, t.messages, t.last_value = rec.ts, t.messages + 1, msg["value"]
                t.publishers.add(key)
                self.events.append(MqttEvent("publish", key, ip, broker, topic=topic, value=msg["value"]))
            for topic in rec.meta.get("mqtt_subscriptions", []):
                client.subscriptions.add(topic)
                self.events.append(MqttEvent("subscribe", key, ip, broker, topic=topic))
        return self.events

    def _client(self, key: str, ip: str, broker: str, ts: float) -> MqttClient:
        c = self.clients.get(key)
        if c is None:
            cid = "" if key.endswith(")") else key
            c = self.clients[key] = MqttClient(key, cid, ip, broker, ts, ts)
        c.last_seen = ts
        c.ip = ip
        return c


def wildcard_scope(topic: str) -> str | None:
    """'all' matches every topic, 'broker' the broker's own $SYS statistics,
    'partial' any other wildcard, None a single topic."""
    if topic.startswith("$SYS"):
        return "broker"
    if topic in ("#", "+/#"):
        return "all"
    if "#" in topic or "+" in topic:
        return "partial"
    return None
