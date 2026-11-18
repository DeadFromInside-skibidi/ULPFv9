"""
ULPF Plugin Interface
======================
The single entry point for any host system embedding ULPF.
"""
from ulpf.plugin.interface import ULPFPlugin
from ulpf.plugin.config import ULPFConfig

__all__ = ["ULPFPlugin", "ULPFConfig"]
