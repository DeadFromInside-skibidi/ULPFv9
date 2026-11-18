"""
MQTT input (IoT), optional extra ``ulpf[mqtt]`` (paho-mqtt 2.x).

Subscribes with a persistent session; with QoS 1/2 a message is acknowledged
to the broker only after it is journaled (manual acks), so the broker
redelivers anything ULPF had not durably accepted. Source = topic.
"""
from __future__ import annotations

import logging
import os
import threading

from ulpf.runtime.inputs.base import Input
from ulpf.runtime.sinks.base import client_ssl_context, env_secret

logger = logging.getLogger(__name__)


class MqttInput(Input):
    def run(self, stop: threading.Event) -> None:
        import paho.mqtt.client as mqtt
        o = self.opts
        client_id = o.get("client_id") or f"ulpf-{self.name}-{os.getpid()}"
        client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=client_id,
                             clean_session=False)
        client.manual_ack_set(True)
        if o.get("username"):
            client.username_pw_set(o["username"], env_secret(o.get("password_env"), "MQTT password"))
        tls = o.get("tls") or {}
        if tls.get("ca") or tls.get("cert") or o.get("port") == 8883:
            client.tls_set_context(client_ssl_context(tls))
        failed = threading.Event()
        error: list[str] = []

        def on_connect(c, _u, _flags, rc, _props=None):
            if getattr(rc, "is_failure", rc != 0):
                error.append(f"connect refused: {rc}")
                failed.set()
                return
            for topic in o["topics"]:
                c.subscribe(topic, qos=o.get("qos", 1))
            self.stats.connections += 1
            logger.info(f"input {self.name}: subscribed to {o['topics']} on {o['host']}:{o['port']}")

        def on_message(c, _u, msg):
            try:
                self.accept(msg.topic, [msg.payload], block=True)
                self.ctx.journal.flush()          # durable before the broker forgets it
                if msg.qos > 0:
                    c.ack(msg.mid, msg.qos)
            except Exception as e:                 # not acked: the broker redelivers
                self.stats.errors += 1
                self.stats.last_error = str(e)

        def on_disconnect(c, _u, _flags, rc, _props=None):
            if not stop.is_set():
                logger.warning(f"input {self.name}: disconnected ({rc}); reconnecting")

        client.on_connect = on_connect
        client.on_message = on_message
        client.on_disconnect = on_disconnect
        client.reconnect_delay_set(1, 60)
        client.connect(o["host"], o["port"], keepalive=30)
        client.loop_start()
        try:
            while not stop.wait(0.5):
                if failed.is_set():
                    raise ConnectionError(error[0] if error else "MQTT connection failed")
        finally:
            client.loop_stop()
            client.disconnect()
