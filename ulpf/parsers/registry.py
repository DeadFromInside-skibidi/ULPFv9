"""Parser Registry — auto-discovers and manages parser plugins."""
from __future__ import annotations
import importlib
import pkgutil
import logging
from typing import Optional
from ulpf.parsers.base import BaseParser

# Explicitly import standard built-in parsers to guarantee availability
# in both development mode and frozen/PyInstaller standalone bundles.
from ulpf.parsers.cef_parser import CEFParser
from ulpf.parsers.csv_parser import CSVParser
from ulpf.parsers.json_parser import JSONParser
from ulpf.parsers.kv_parser import KVParser
from ulpf.parsers.leef_parser import LEEFParser
from ulpf.parsers.syslog_parser import SyslogParser
from ulpf.parsers.w3c_parser import W3CParser
from ulpf.parsers.xml_parser import XMLParser

_BUILTIN_PARSERS = [
    CEFParser,
    CSVParser,
    JSONParser,
    KVParser,
    LEEFParser,
    SyslogParser,
    W3CParser,
    XMLParser,
]

logger = logging.getLogger(__name__)


class ParserRegistry:
    def __init__(self, plugin_policy: dict | None = None):
        self._parsers: dict[str, BaseParser] = {}
        self._format_map: dict[str, BaseParser] = {}
        self._register_builtins()
        self._auto_discover()
        # Installed ``ulpf.parsers`` entry-point plugins, tried before built-ins
        self.plugins: list[BaseParser] = []
        self.plugin_infos: list = []
        try:
            from ulpf.parsers.plugins import discover
            self.plugin_infos = discover(plugin_policy)
        except Exception as e:
            logger.warning(f"Parser plugin discovery failed: {e}")
        for info in self.plugin_infos:
            if info.loaded:
                self.plugins.append(info.parser)
                self._parsers[info.parser.parser_id] = info.parser

    def _register_builtins(self):
        """Always register the core built-in parsers directly."""
        for parser_cls in _BUILTIN_PARSERS:
            try:
                self.register(parser_cls())
            except Exception as e:
                logger.warning(f"Could not load built-in parser {parser_cls.__name__}: {e}")

    def _auto_discover(self):
        """Discover any additional custom parser modules in the parsers package."""
        try:
            import ulpf.parsers as pkg
            if hasattr(pkg, "__path__"):
                for _importer, modname, _ispkg in pkgutil.iter_modules(pkg.__path__):
                    if modname in ("base", "registry", "__init__", "cef_parser", "csv_parser", "json_parser", "kv_parser", "leef_parser", "syslog_parser", "w3c_parser", "xml_parser"):
                        continue
                    try:
                        module = importlib.import_module(f"ulpf.parsers.{modname}")
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (isinstance(attr, type)
                                    and issubclass(attr, BaseParser)
                                    and attr is not BaseParser
                                    and not getattr(attr, '__abstractmethods__', None)):
                                self.register(attr())
                    except Exception as e:
                        logger.warning(f"Could not load custom parser module {modname}: {e}")
        except Exception as e:
            logger.debug(f"Parser auto-discovery skipped: {e}")

    def register(self, parser: BaseParser):
        self._parsers[parser.parser_id] = parser
        for fmt in parser.supported_formats:
            self._format_map[fmt.lower()] = parser

    def get_parser_for_format(self, fmt: str) -> Optional[BaseParser]:
        return self._format_map.get(fmt.lower())

    def reset_stream_state(self) -> None:
        """Clear per-stream parser state (W3C #Fields, CSV headers)."""
        for parser in self._parsers.values():
            parser.reset_state()

    def get_parser_by_id(self, pid: str) -> Optional[BaseParser]:
        return self._parsers.get(pid)

    def get_all_parsers(self) -> list[BaseParser]:
        return list(self._parsers.values())

    def list_parsers(self) -> list[dict]:
        return [p.get_info() for p in self._parsers.values()]

    def list_formats(self) -> list[str]:
        return list(self._format_map.keys())
