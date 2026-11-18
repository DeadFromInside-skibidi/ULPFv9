"""Pipeline inputs."""
from __future__ import annotations

import importlib

from ulpf.config.components import INPUTS


def build_input(options: dict, ctx):
    from ulpf.runtime.inputs.native import native_class
    comp = INPUTS[options["type"]]
    cls = native_class(options) or getattr(importlib.import_module(comp.module), comp.cls)
    return cls(options["name"], options, ctx)
