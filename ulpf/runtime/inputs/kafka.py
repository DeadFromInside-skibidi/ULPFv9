"""
Kafka input, optional extra ``ulpf[kafka]`` (confluent-kafka).

Consumer-group offsets are committed only after the polled batch is in the
journal and flushed to disk: at-least-once from Kafka, durable in ULPF.
Source = ``topic/partition``.
"""
from __future__ import annotations

import threading

from ulpf.runtime.inputs.base import Input
from ulpf.runtime.sinks.base import env_secret


class KafkaInput(Input):
    def run(self, stop: threading.Event) -> None:
        from confluent_kafka import Consumer, KafkaException
        o = self.opts
        conf = {"bootstrap.servers": ",".join(o["brokers"]), "group.id": o.get("group_id") or "ulpf",
                "enable.auto.commit": False, "auto.offset.reset": "earliest"}
        tls = o.get("tls") or {}
        if tls.get("ca") or tls.get("cert") or o.get("sasl_mechanism"):
            conf["security.protocol"] = "SASL_SSL" if o.get("sasl_mechanism") else "SSL"
            if tls.get("ca"):
                conf["ssl.ca.location"] = tls["ca"]
            if tls.get("cert"):
                conf.update({"ssl.certificate.location": tls["cert"], "ssl.key.location": tls.get("key")})
        if o.get("sasl_mechanism"):
            conf.update({"sasl.mechanism": o["sasl_mechanism"], "sasl.username": o.get("username"),
                         "sasl.password": env_secret(o.get("password_env"), "Kafka password")})
        from ulpf.runtime.egress import vet_endpoints
        vet_endpoints(o["brokers"], "kafka input")   # librdkafka bypasses the audit hook
        consumer = Consumer(conf)
        consumer.subscribe(o["topics"])
        try:
            while not stop.is_set():
                msgs = consumer.consume(num_messages=2000, timeout=0.5)
                if not msgs:
                    continue
                by_source: dict[str, list[bytes]] = {}
                for m in msgs:
                    if m.error():
                        if m.error().fatal():
                            raise KafkaException(m.error())
                        continue
                    if m.value() is not None:
                        by_source.setdefault(f"{m.topic()}/{m.partition()}", []).append(m.value())
                for source, recs in by_source.items():
                    self.accept(source, recs, block=True)
                self.ctx.journal.flush()
                consumer.commit(asynchronous=False)
        finally:
            consumer.close()
