"""
Kafka output (optional extra ``ulpf[kafka]``, needs ``confluent-kafka``).

Idempotent producer with ``acks=all``; records are keyed (default: source IP)
so one source's events stay ordered within a partition. A segment is acked
only after every message in it is confirmed by the brokers.
"""
from __future__ import annotations

from ulpf.engine.views import apply_view
from ulpf.runtime.buffer import Segment
from ulpf.runtime.retry import PermanentError, RetriableError
from ulpf.runtime.sinks.base import Sink, dumps, env_secret


class KafkaSink(Sink):
    remote = True

    def encode(self, events: list[dict]) -> bytes:
        from ulpf.runtime.router import get_path
        key_field = self.opts.get("key_field") or "source_ip"
        path = {"source_ip": "source.ip"}.get(key_field, key_field)
        out = []
        for e in events:
            k = get_path(e, path)
            out.append(dumps({"k": None if k is None else str(k), "v": apply_view(e, self.view)}))
        return b"\n".join(out) + b"\n"

    def open(self) -> None:
        from confluent_kafka import Producer
        o = self.opts
        conf = {"bootstrap.servers": ",".join(o["brokers"]), "enable.idempotence": True, "acks": "all",
                "compression.type": o.get("compression") or "lz4", "linger.ms": 20}
        tls = o.get("tls") or {}
        if tls.get("ca") or tls.get("cert") or o.get("sasl_mechanism"):
            conf["security.protocol"] = "SASL_SSL" if o.get("sasl_mechanism") else "SSL"
            if tls.get("ca"):
                conf["ssl.ca.location"] = tls["ca"]
            if tls.get("cert"):
                conf["ssl.certificate.location"] = tls["cert"]
                conf["ssl.key.location"] = tls.get("key")
        if o.get("sasl_mechanism"):
            conf.update({"sasl.mechanism": o["sasl_mechanism"], "sasl.username": o.get("username"),
                         "sasl.password": env_secret(o.get("password_env"), "Kafka password")})
        from ulpf.runtime.egress import vet_endpoints
        vet_endpoints(o["brokers"], f"kafka output {self.name!r}")   # librdkafka bypasses the audit hook
        self.producer = Producer(conf)

    def deliver(self, payload: bytes, seg: Segment) -> None:
        import orjson
        errors: list = []

        def done(err, _msg):
            if err is not None:
                errors.append(err)

        topic = self.opts["topic"]
        for line in self.records(payload):
            d = orjson.loads(line)
            while True:
                try:
                    self.producer.produce(topic, value=dumps(d["v"]),
                                          key=None if d["k"] is None else d["k"].encode(), on_delivery=done)
                    break
                except BufferError:
                    self.producer.poll(0.5)
        remaining = self.producer.flush(120)
        if remaining:
            raise RetriableError(f"{remaining} Kafka message(s) not confirmed in time")
        if errors:
            fatal = [e for e in errors if not e.retriable()]
            if fatal:
                raise PermanentError(f"Kafka rejected messages: {fatal[0]}")
            raise RetriableError(f"Kafka delivery failed: {errors[0]}")

    def close(self) -> None:
        p = getattr(self, "producer", None)
        if p is not None:
            p.flush(10)
