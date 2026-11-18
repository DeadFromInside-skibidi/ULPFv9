"""Output sinks."""
from __future__ import annotations

import importlib

from ulpf.config.components import OUTPUTS


def sink_class(type_: str):
    comp = OUTPUTS[type_]
    return getattr(importlib.import_module(comp.module), comp.cls)


def build_sink(options: dict, context: dict | None = None):
    return sink_class(options["type"])(options["name"], options, context)
