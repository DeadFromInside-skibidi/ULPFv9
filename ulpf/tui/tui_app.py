"""
ULPF Terminal User Interface (TUI)
====================================
A command-line tool interface styled with RGB colours, ASCII art,
formatted spacing, and dot/dash/star separators.

NOT a dashboard — this is a proper terminal tool like nmap, metasploit,
or sqlmap. Works in SSH, Docker, WSL, and air-gapped environments.

Dual mode:
  • Menu-driven (default) — press a number to pick an action
  • Command mode — type commands manually like a shell

Usage:
    python -m ulpf.main tui
    python -m ulpf.tui.tui_app
"""
from __future__ import annotations

import glob
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

_PLUGIN = None


def _get_plugin():
    """One engine instance per TUI session (store connection + learner thread)."""
    global _PLUGIN
    if _PLUGIN is None:
        from ulpf.plugin.interface import ULPFPlugin
        _PLUGIN = ULPFPlugin()
        _PLUGIN.initialize()
        _PLUGIN.start()
    return _PLUGIN


def _setup_windows_utf8():
    """Force UTF-8 output on Windows to support Unicode/ANSI characters."""
    if sys.platform == "win32":
        import ctypes
        try:
            # Enable VT processing for ANSI escape codes
            kernel32 = ctypes.windll.kernel32
            STD_OUTPUT_HANDLE = -11
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        except Exception:
            pass
        # Force UTF-8 encoding on stdout/stderr
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        os.environ["PYTHONIOENCODING"] = "utf-8"


def _check_dependencies():
    """Check if rich is available."""
    try:
        import rich  # noqa: F401
    except ImportError:
        print("Missing dependency: rich")
        print("Install with: pip install rich")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
# COLOUR PALETTE
# ═══════════════════════════════════════════════════════════════════════════

# Matrix green, cyber cyan, amber, red — the four pillars
C_GREEN    = "#00ff41"
C_CYAN     = "#00d4ff"
C_AMBER    = "#ffb000"
C_RED      = "#ff0040"
C_DIM      = "#555570"
C_WHITE    = "#e0e0f0"
C_PURPLE   = "#bf7fff"
C_GREY     = "#7a7a8e"
C_DARKGREEN = "#008f11"

# Shorthand style strings
S_BANNER   = f"bold {C_CYAN}"
S_TITLE    = f"bold {C_CYAN}"
S_SUCCESS  = f"bold {C_GREEN}"
S_WARN     = f"bold {C_AMBER}"
S_ERROR    = f"bold {C_RED}"
S_DIM      = f"{C_DIM}"
S_KEY      = f"bold {C_GREEN}"
S_VAL      = f"bold {C_WHITE}"
S_PROMPT   = f"bold {C_GREEN}"
S_STAR     = f"bold {C_AMBER}"
S_BULLET   = f"{C_CYAN}"
S_DIAMOND  = f"bold {C_PURPLE}"


# ═══════════════════════════════════════════════════════════════════════════
# ASCII ART BANNER
# ═══════════════════════════════════════════════════════════════════════════

BANNER_ART = r"""
  ██╗   ██╗██╗     ██████╗ ███████╗
  ██║   ██║██║     ██╔══██╗██╔════╝
  ██║   ██║██║     ██████╔╝█████╗  
  ██║   ██║██║     ██╔═══╝ ██╔══╝  
  ╚██████╔╝███████╗██║     ██║     
   ╚═════╝ ╚══════╝╚═╝     ╚═╝    
"""

from ulpf import __version__

TAGLINE = "Universal Log Pre-processing Framework"
VERSION = f"v{__version__}"


def _print_banner(console):
    """Print the startup ASCII banner with system info."""
    w = 66

    console.print()
    console.print(f"  [{S_DIM}]╔{'═' * w}╗[/]")
    console.print(f"  [{S_DIM}]║{' ' * w}║[/]")

    for line in BANNER_ART.strip().splitlines():
        padded = line.ljust(w)
        console.print(f"  [{S_DIM}]║[/]  [{S_BANNER}]{padded}[/][{S_DIM}]║[/]")

    console.print(f"  [{S_DIM}]║{' ' * w}║[/]")

    tag_line = f"   {TAGLINE}  {VERSION}"
    console.print(f"  [{S_DIM}]║[/]  [{C_GREEN}]{tag_line.ljust(w)}[/][{S_DIM}]║[/]")

    sub_line = "   ── Air-gapped ── Headless ── Forensic-ready ──"
    console.print(f"  [{S_DIM}]║[/]  [{S_DIM}]{sub_line.ljust(w)}[/][{S_DIM}]║[/]")

    console.print(f"  [{S_DIM}]║{' ' * w}║[/]")
    console.print(f"  [{S_DIM}]╚{'═' * w}╝[/]")
    console.print()


def _print_sysinfo(console):
    """Print system information block."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    os_name = f"{platform.system()} {platform.release()}"

    # Count demo files
    demo_dir = os.path.join(PROJECT_ROOT, "demo_data")
    demo_count = len(glob.glob(os.path.join(demo_dir, "*.log"))) if os.path.isdir(demo_dir) else 0

    console.print(f"  [{S_STAR}]★[/] [{S_KEY}]System[/]    [{S_DIM}]:[/] [{S_VAL}]{os_name} │ Python {py_ver}[/]")
    console.print(f"  [{S_STAR}]★[/] [{S_KEY}]Database[/]  [{S_DIM}]:[/] [{S_VAL}]DuckDB (ulpf.duckdb)[/]")
    console.print(f"  [{S_STAR}]★[/] [{S_KEY}]Demo Data[/] [{S_DIM}]:[/] [{S_VAL}]{demo_count} log files available[/]")
    console.print(f"  [{S_STAR}]★[/] [{S_KEY}]Started[/]   [{S_DIM}]:[/] [{S_VAL}]{now}[/]")
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
# HELP / COMMAND REFERENCE
# ═══════════════════════════════════════════════════════════════════════════

def _print_help(console):
    """Print the full beginner-friendly command reference."""
    sep = f"[{S_DIM}]{'─' * 62}[/]"

    console.print()
    console.print(f"  [{S_TITLE}]═══════════════════════════════════════════════════════════════[/]")
    console.print(f"  [{S_TITLE}] COMMAND REFERENCE ── What each feature does & how to use it[/]")
    console.print(f"  [{S_TITLE}]═══════════════════════════════════════════════════════════════[/]")
    console.print()

    cmds = [
        (
            "process <file>",
            "Parse a raw log file. Extracts security events, auto-detects\n"
            "                        format (CEF, LEEF, Syslog, JSON, XML, KV, W3C),\n"
            "                        stores to database, runs anomaly detection.\n"
            f"                        [{S_DIM}]Example: process demo_data/mixed_formats.log[/]"
        ),
        (
            "stats",
            "Show database statistics ── total events, format breakdown,\n"
            "                        category distribution, severity counts."
        ),
        (
            "search <query>",
            "Search stored events by keyword. Matches IP addresses,\n"
            "                        hostnames, actions, messages, categories.\n"
            f"                        [{S_DIM}]Example: search 10.0.0.1[/]"
        ),
        (
            "correlate",
            "Group related events into attack chains. Uses time-window\n"
            "                        correlation to find multi-stage attacks.\n"
            "                        Shows kill-chain stages and risk scores."
        ),
        (
            "forensic",
            "Build a forensic evidence package with cryptographic integrity\n"
            "                        (SHA-256 hash chain). Exports court-ready evidence\n"
            "                        bundles to the output/ directory."
        ),
        (
            "export \\[path]",
            "Export all stored events to a JSON file.\n"
            f"                        [{S_DIM}]Default: output/export.json[/]"
        ),
        (
            "demo",
            "Run a full demo using ALL sample log files in demo_data/.\n"
            "                        Great for first-time users to see ULPF in action!"
        ),
        (
            "clear",
            "Clear the terminal screen."
        ),
        (
            "mode",
            "Switch between MENU mode and COMMAND mode."
        ),
        (
            "help",
            "Show this command reference again."
        ),
        (
            "quit / exit",
            "Exit ULPF."
        ),
    ]

    for cmd_name, desc in cmds:
        console.print(f"  [{S_BULLET}]▸[/] [{S_KEY}]{cmd_name:20s}[/] {desc}")
        console.print()

    console.print(f"  {sep}")
    console.print(f"  [{S_STAR}]★[/] [{C_GREEN}]TIP:[/] Type '[bold]demo[/]' to see ULPF in action with sample data!")
    console.print(f"  {sep}")
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
# MENU DISPLAY
# ═══════════════════════════════════════════════════════════════════════════

def _print_menu(console):
    """Print the menu-driven interface."""
    w = 42

    console.print()
    console.print(f"  [{S_DIM}]╔{'═' * w}╗[/]")
    console.print(f"  [{S_DIM}]║[/]  [{S_TITLE}]{'ULPF ── MAIN MENU':^{w - 2}}[/]  [{S_DIM}]║[/]")
    console.print(f"  [{S_DIM}]╠{'═' * w}╣[/]")
    console.print(f"  [{S_DIM}]║{' ' * w}║[/]")

    items = [
        ("1", "◆", "Process Log File",         C_GREEN),
        ("2", "◆", "View Database Stats",       C_CYAN),
        ("3", "◆", "Search Events",             C_CYAN),
        ("4", "◆", "Correlate Events",          C_PURPLE),
        ("5", "◆", "Build Forensic Chain",      C_PURPLE),
        ("6", "◆", "Export to JSON",            C_CYAN),
        ("7", "★", "Run Demo  (Recommended!)",  C_AMBER),
        ("8", "◆", "Switch to Command Mode",    C_DIM),
        ("h", "◆", "Help & Command Reference",  C_GREEN),
        ("q", "◆", "Quit",                      C_RED),
    ]

    for key, icon, label, colour in items:
        # Escape brackets so Rich doesn't interpret [h] or [q] as styles
        entry = f"   [{colour}]\\[{key}][/] [{colour}]{icon}[/] {label}"
        # We need to calculate visible length for padding
        # Just right-pad the raw label text
        pad_label = f"   [{key}] {icon} {label}"
        pad_needed = w - len(pad_label)
        if pad_needed < 0:
            pad_needed = 0
        console.print(f"  [{S_DIM}]║[/]{entry}{' ' * pad_needed}  [{S_DIM}]║[/]")

    console.print(f"  [{S_DIM}]║{' ' * w}║[/]")
    console.print(f"  [{S_DIM}]╚{'═' * w}╝[/]")
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT HELPERS — dots, stars, bars (NO rich panels / tables)
# ═══════════════════════════════════════════════════════════════════════════

def _section_header(console, title: str):
    """Print a star-prefixed section header with a dashed line."""
    dash_len = 58 - len(title)
    if dash_len < 4:
        dash_len = 4
    console.print(f"  [{S_STAR}]★[/] [{S_TITLE}]{title}[/] [{S_DIM}]{'─' * dash_len}[/]")


def _kv_line(console, key: str, value: str, key_width: int = 22,
             val_style: str = S_VAL, dots: bool = True):
    """Print a key-value line with dot separators."""
    if dots:
        dot_count = key_width - len(key)
        if dot_count < 2:
            dot_count = 2
        dots_str = " " + "·" * dot_count + " "
        console.print(f"    [{S_KEY}]{key}[/][{S_DIM}]{dots_str}[/][{val_style}]{value}[/]")
    else:
        padded = key.ljust(key_width)
        console.print(f"    [{S_KEY}]{padded}[/] [{val_style}]{value}[/]")


def _bar_line(console, label: str, count: int, max_count: int,
              bar_width: int = 24, colour: str = C_CYAN):
    """Print a bar-chart line using block characters."""
    if max_count <= 0:
        max_count = 1
    filled = int((count / max_count) * bar_width)
    if filled < 1 and count > 0:
        filled = 1
    bar = "█" * filled + "░" * (bar_width - filled)
    pct = count * 100 // max_count
    console.print(
        f"    [{S_DIM}]·[/] [{S_KEY}]{label:16s}[/] [{colour}]{bar}[/] [{S_VAL}]{count}[/]"
        f"  [{S_DIM}]({pct}%)[/]"
    )


def _divider(console, char: str = "─", width: int = 62):
    """Print a dim divider line."""
    console.print(f"  [{S_DIM}]{char * width}[/]")


def _blank(console):
    """Print an empty line."""
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════════════════

def _cmd_process(console, filepath: str):
    """Process a single log file with styled output."""
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn

    if not filepath:
        filepath = _ask(console, "Log file path",
                        os.path.join(PROJECT_ROOT, "demo_data", "mixed_formats.log"))

    if not os.path.isfile(filepath):
        console.print(f"  [{S_ERROR}]✗ File not found:[/] {filepath}")
        return

    console.print()
    _divider(console, "─")
    console.print(f"  [{S_TITLE}]Processing:[/] [{C_WHITE}]{filepath}[/]")
    _divider(console, "─")
    _blank(console)

    from ulpf.plugin.interface import ULPFPlugin

    plugin = _get_plugin()

    pipeline = plugin.pipeline
    pipeline.reset_metrics()
    db = plugin.storage
    detector = plugin.anomaly_detector

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    # Progress bar — inline, no widgets
    with Progress(
        TextColumn(f"  [{C_GREEN}]▸[/] [{S_DIM}]Parsing[/]"),
        BarColumn(bar_width=40, complete_style=C_GREEN, finished_style=C_GREEN),
        TextColumn(f"[{S_DIM}]{{task.percentage:>3.0f}}%[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("parse", total=len(lines))
        results = []
        for line in lines:
            r = pipeline.process_line(line)
            results.append(r)
            progress.advance(task)

    events = [r["event"] for r in results if r.get("success")]
    failed_count = len(results) - len(events)

    # Store
    stored = db.insert_batch(events)

    # Anomalies
    anomalies = detector.analyse_batch(events)
    for a in anomalies:
        db.store_anomaly(a)

    metrics = pipeline.get_metrics()
    success_rate = f"{len(events) * 100 // max(len(results), 1)}%"

    # ── Results ──
    _section_header(console, "Results")
    _kv_line(console, "Lines processed", str(len(results)))
    _kv_line(console, "Parsed OK", f"{len(events)}  ({success_rate})",
             val_style=S_SUCCESS)
    _kv_line(console, "Failed", str(failed_count),
             val_style=S_ERROR if failed_count > 0 else S_VAL)
    _kv_line(console, "Stored to DB", str(stored))
    _kv_line(console, "Anomalies", str(len(anomalies)),
             val_style=S_ERROR if anomalies else S_VAL)
    _blank(console)

    # ── Format Distribution ──
    fmt_dist = metrics.get("format_distribution", {})
    if fmt_dist:
        _section_header(console, "Format Distribution")
        max_fmt = max(fmt_dist.values(), default=1)
        for fmt, cnt in sorted(fmt_dist.items(), key=lambda x: -x[1]):
            _bar_line(console, fmt, cnt, max_fmt)
        _blank(console)

    # ── Category Distribution ──
    cats: dict[str, int] = {}
    for e in events:
        c = e.get("category", "other")
        cats[c] = cats.get(c, 0) + 1
    if cats:
        _section_header(console, "Categories")
        max_cat = max(cats.values(), default=1)
        for cat, cnt in sorted(cats.items(), key=lambda x: -x[1]):
            _bar_line(console, cat, cnt, max_cat, colour=C_AMBER)
        _blank(console)

    # ── Severity Distribution ──
    sev_labels = {
        0: "info", 1: "info", 2: "info", 3: "low", 4: "low",
        5: "med", 6: "med", 7: "high", 8: "high", 9: "crit", 10: "fatal"
    }
    sev_dist: dict[str, int] = {}
    for e in events:
        s = e.get("severity", 0)
        label = sev_labels.get(s, str(s))
        sev_dist[label] = sev_dist.get(label, 0) + 1
    if sev_dist:
        _section_header(console, "Severity Distribution")
        max_sev = max(sev_dist.values(), default=1)
        sev_order = ["info", "low", "med", "high", "crit", "fatal"]
        sev_colours = {
            "info": C_GREEN, "low": C_GREEN, "med": C_AMBER,
            "high": C_AMBER, "crit": C_RED, "fatal": C_RED,
        }
        for lbl in sev_order:
            cnt = sev_dist.get(lbl, 0)
            if cnt > 0:
                _bar_line(console, lbl, cnt, max_sev,
                          colour=sev_colours.get(lbl, C_CYAN))
        _blank(console)

    # ── Anomalies ──
    if anomalies:
        _section_header(console, "Anomalies Detected")
        for a in anomalies[:10]:
            risk = a.get("risk", "?").upper()
            if risk in ("CRITICAL", "HIGH"):
                risk_style = S_ERROR
            elif risk == "MEDIUM":
                risk_style = S_WARN
            else:
                risk_style = S_KEY
            desc = a.get("description", "")[:80]
            atype = a.get("type", "unknown")
            console.print(
                f"    [{risk_style}][{risk:8s}][/] [{C_AMBER}]{atype}[/] "
                f"[{S_DIM}]──[/] {desc}"
            )
        _blank(console)

    # ── Top Source IPs ──
    src_ips: dict[str, int] = {}
    for e in events:
        ip = e.get("source", {}).get("ip")
        if ip:
            src_ips[ip] = src_ips.get(ip, 0) + 1
    if src_ips:
        _section_header(console, "Top Source IPs")
        for ip, cnt in sorted(src_ips.items(), key=lambda x: -x[1])[:5]:
            console.print(
                f"    [{S_DIM}]·[/] [{C_GREEN}]{ip:18s}[/] [{S_VAL}]{cnt:3d} events[/]"
            )
        _blank(console)

    _divider(console, "═")
    console.print(f"  [{S_SUCCESS}]✓ Processing complete.[/]")
    _blank(console)

    return events, anomalies


def _cmd_stats(console):
    """Show database statistics."""
    from ulpf.plugin.interface import ULPFPlugin
    plugin = _get_plugin()
    db = plugin.storage
    stats = db.stats()

    _blank(console)
    _section_header(console, "Database Statistics")
    _kv_line(console, "Total Events", f"{stats['total_events']:,}")
    _blank(console)

    by_format = stats.get("by_format", {})
    if by_format:
        _section_header(console, "Format Breakdown")
        max_f = max(by_format.values(), default=1)
        for fmt, cnt in sorted(by_format.items(), key=lambda x: -x[1]):
            _bar_line(console, fmt, cnt, max_f)
        _blank(console)

    by_cat = stats.get("by_category", {})
    if by_cat:
        _section_header(console, "Category Breakdown")
        max_c = max(by_cat.values(), default=1)
        for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
            _bar_line(console, cat, cnt, max_c, colour=C_AMBER)
        _blank(console)

    if stats["total_events"] == 0:
        console.print(f"  [{S_DIM}]Database is empty. Run 'process' or 'demo' first![/]")
        _blank(console)


def _cmd_search(console, query: str):
    """Search events by keyword."""
    if not query:
        query = _ask(console, "Search query", "")
    if not query:
        console.print(f"  [{S_DIM}]No query provided.[/]")
        return

    from ulpf.plugin.interface import ULPFPlugin
    plugin = _get_plugin()
    db = plugin.storage
    results = db.search(query, limit=20)

    _blank(console)
    _section_header(console, f"Search Results for '{query}'")

    if not results:
        console.print(f"  [{S_DIM}]  No results found.[/]")
        _blank(console)
        return

    console.print(f"  [{S_DIM}]  Found {len(results)} event(s)[/]")
    _blank(console)

    for i, e in enumerate(results, 1):
        sev = e.get("severity", 0)
        if sev >= 8:
            sev_style = S_ERROR
        elif sev >= 5:
            sev_style = S_WARN
        else:
            sev_style = S_KEY

        ts = str(e.get("timestamp", ""))[:19]
        cat = e.get("category", "")
        src = e.get("source", {}).get("ip", "─")
        dst = e.get("destination", {}).get("ip", "─")
        action = e.get("action", "─")
        fmt = e.get("raw_format", "─")

        console.print(
            f"  [{S_DIM}]{i:3d}.[/] [{S_DIM}]{ts}[/]  "
            f"[{C_AMBER}]{cat:14s}[/]  "
            f"[{sev_style}]sev={sev}[/]  "
            f"[{C_GREEN}]{src}[/] → [{C_RED}]{dst}[/]  "
            f"[{S_DIM}]{action}[/]  [{C_CYAN}]{fmt}[/]"
        )

    _blank(console)


def _cmd_correlate(console):
    """Run correlation analysis."""
    from ulpf.plugin.interface import ULPFPlugin
    from ulpf.intelligence.correlation import EventCorrelator

    plugin = _get_plugin()
    db = plugin.storage
    events = db.query(limit=200)

    if not events:
        console.print(f"  [{S_DIM}]No events in database. Run 'process' or 'demo' first![/]")
        return

    _blank(console)
    console.print(f"  [{S_TITLE}]Correlating {len(events)} events...[/]")

    correlator = EventCorrelator(60.0)
    correlator.add_events(events)
    groups = correlator.correlate()

    _blank(console)
    _section_header(console, f"Correlation Results — {len(groups)} groups")
    _blank(console)

    if not groups:
        console.print(f"  [{S_DIM}]  No correlation groups found.[/]")
        _blank(console)
        return

    for g in groups:
        d = g.to_dict()
        risk = d["risk_score"]
        if risk > 7:
            risk_colour = C_RED
        elif risk > 4:
            risk_colour = C_AMBER
        else:
            risk_colour = C_GREEN

        console.print(
            f"  [{S_DIM}]├──[/] [{S_VAL}]{d['correlation_id']}[/]"
        )
        console.print(
            f"  [{S_DIM}]│[/]   [{S_KEY}]Events[/] [{S_DIM}]·····[/] "
            f"[{S_VAL}]{d['event_count']}[/]    "
            f"[{S_KEY}]Risk[/] [{S_DIM}]·······[/] "
            f"[{risk_colour}]{risk:.1f}/10[/]"
        )
        if d.get("kill_chain_stages"):
            stages = ", ".join(d["kill_chain_stages"])
            console.print(
                f"  [{S_DIM}]│[/]   [{S_KEY}]Kill-chain[/] [{S_DIM}]·[/] "
                f"[{C_AMBER}]{stages}[/]"
            )
        summary = d.get("summary", "")[:100]
        console.print(f"  [{S_DIM}]│[/]   {summary}")
        console.print(f"  [{S_DIM}]│[/]")

    _blank(console)


def _cmd_forensic(console):
    """Build forensic evidence chain."""
    from ulpf.plugin.interface import ULPFPlugin
    from ulpf.intelligence.forensic import ForensicBuilder

    plugin = _get_plugin()
    db = plugin.storage
    builder = ForensicBuilder()
    events = db.query(limit=100)

    if not events:
        console.print(f"  [{S_DIM}]No events in database. Run 'process' or 'demo' first![/]")
        return

    _blank(console)
    console.print(f"  [{S_TITLE}]Building evidence chain from {len(events)} events...[/]")
    _blank(console)

    chain = builder.build_from_events(events, description="TUI-generated chain")
    integrity = chain.verify_integrity()

    is_valid = integrity["valid"]
    status_icon = "✓" if is_valid else "✗"
    status_text = "VALID" if is_valid else "INVALID"
    status_style = S_SUCCESS if is_valid else S_ERROR

    _section_header(console, "Forensic Evidence Chain")
    _kv_line(console, "Chain ID", chain.chain_id)
    _kv_line(console, "Evidence items", str(len(chain.items)))
    _kv_line(console, "SHA-256 Hash", f"{chain.chain_hash[:40]}...")
    _kv_line(console, "Integrity",
             f"{status_icon} {status_text}",
             val_style=status_style)

    filepath = builder.export_package(chain.chain_id)
    _kv_line(console, "Exported to", str(filepath), val_style=S_SUCCESS)
    _blank(console)

    _divider(console, "═")
    console.print(f"  [{S_SUCCESS}]✓ Forensic package ready.[/]")
    _blank(console)


def _cmd_export(console, export_path: str):
    """Export events to JSON."""
    from ulpf.plugin.interface import ULPFPlugin
    plugin = _get_plugin()
    db = plugin.storage
    events = db.query(limit=10000)

    if not events:
        console.print(f"  [{S_DIM}]No events to export. Run 'process' or 'demo' first![/]")
        return

    if not export_path:
        export_path = _ask(console, "Export path",
                           os.path.join(PROJECT_ROOT, "output", "export.json"))

    os.makedirs(os.path.dirname(export_path), exist_ok=True)
    with open(export_path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2, default=str)

    _blank(console)
    console.print(
        f"  [{S_SUCCESS}]✓[/] Exported [{S_VAL}]{len(events)}[/] events "
        f"to [{C_CYAN}]{export_path}[/]"
    )
    _blank(console)


def _cmd_demo(console):
    """Run the demo — process all files in demo_data/."""
    demo_dir = os.path.join(PROJECT_ROOT, "demo_data")
    log_files = sorted(glob.glob(os.path.join(demo_dir, "*.log")))

    if not log_files:
        console.print(f"  [{S_ERROR}]✗ No .log files found in demo_data/[/]")
        return

    _blank(console)
    console.print(f"  [{S_TITLE}]═══════════════════════════════════════════════════════════════[/]")
    console.print(f"  [{S_TITLE}]  ULPF DEMO ── Processing {len(log_files)} sample log files[/]")
    console.print(f"  [{S_TITLE}]═══════════════════════════════════════════════════════════════[/]")
    _blank(console)

    total_events = 0
    total_anomalies = 0

    for i, filepath in enumerate(log_files, 1):
        fname = os.path.basename(filepath)
        console.print(f"  [{S_DIM}]──────────────────────────────────────────────────────────[/]")
        console.print(f"  [{S_STAR}]★[/] [{S_TITLE}]File {i}/{len(log_files)}:[/] [{C_WHITE}]{fname}[/]")
        console.print(f"  [{S_DIM}]──────────────────────────────────────────────────────────[/]")

        result = _cmd_process(console, filepath)
        if result:
            events, anomalies = result
            total_events += len(events)
            total_anomalies += len(anomalies)

    # Summary
    console.print(f"  [{S_TITLE}]═══════════════════════════════════════════════════════════════[/]")
    console.print(f"  [{S_TITLE}]  DEMO COMPLETE[/]")
    console.print(f"  [{S_TITLE}]═══════════════════════════════════════════════════════════════[/]")
    _blank(console)
    _kv_line(console, "Files processed", str(len(log_files)))
    _kv_line(console, "Total events", str(total_events), val_style=S_SUCCESS)
    _kv_line(console, "Total anomalies", str(total_anomalies),
             val_style=S_ERROR if total_anomalies else S_VAL)
    _blank(console)
    console.print(
        f"  [{S_DIM}]Try 'stats', 'search', 'correlate', or 'forensic' "
        f"to explore the data![/]"
    )
    _blank(console)


# ═══════════════════════════════════════════════════════════════════════════
# INPUT HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _ask(console, label: str, default: str = "") -> str:
    """Prompt for input with a styled prompt line."""
    from rich.prompt import Prompt
    default_hint = f" [{S_DIM}](default: {default})[/]" if default else ""
    try:
        val = Prompt.ask(
            f"  [{S_KEY}]{label}[/]{default_hint}",
            default=default,
            console=console,
        )
        return val.strip()
    except (EOFError, KeyboardInterrupt):
        return default


# ═══════════════════════════════════════════════════════════════════════════
# MAIN INTERACTIVE LOOP
# ═══════════════════════════════════════════════════════════════════════════

def launch_rich_dashboard():
    """
    Launch the CLI-style terminal interface.
    Dual mode: menu-driven (default) or command mode.
    """
    from rich.console import Console

    console = Console(force_terminal=True)

    # ── Startup ──
    console.clear()
    _print_banner(console)
    _print_sysinfo(console)
    _print_help(console)

    # Track current mode
    menu_mode = True

    while True:
        try:
            if menu_mode:
                _print_menu(console)
                choice = _ask(console, "ulpf»", "")
                choice = choice.strip().lower()

                if choice in ("q", "quit", "exit"):
                    break
                elif choice == "1":
                    _cmd_process(console, "")
                elif choice == "2":
                    _cmd_stats(console)
                elif choice == "3":
                    _cmd_search(console, "")
                elif choice == "4":
                    _cmd_correlate(console)
                elif choice == "5":
                    _cmd_forensic(console)
                elif choice == "6":
                    _cmd_export(console, "")
                elif choice == "7":
                    _cmd_demo(console)
                elif choice == "8" or choice == "mode":
                    menu_mode = False
                    console.print()
                    console.print(
                        f"  [{S_SUCCESS}]✓ Switched to COMMAND mode.[/] "
                        f"[{S_DIM}]Type commands directly. "
                        f"Type 'mode' to switch back to menu.[/]"
                    )
                    _blank(console)
                elif choice in ("h", "help"):
                    _print_help(console)
                elif choice == "clear":
                    console.clear()
                    _print_banner(console)
                else:
                    if choice:
                        console.print(
                            f"  [{S_DIM}]Unknown option '{choice}'. "
                            f"Press 'h' for help.[/]"
                        )
            else:
                # ── Command Mode ──
                try:
                    raw = console.input(f"  [{C_GREEN}]ulpf:cmd»[/] ")
                except (EOFError, KeyboardInterrupt):
                    break

                raw = raw.strip()
                if not raw:
                    continue

                parts = raw.split(maxsplit=1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd in ("q", "quit", "exit"):
                    break
                elif cmd == "process":
                    _cmd_process(console, arg)
                elif cmd == "stats":
                    _cmd_stats(console)
                elif cmd == "search":
                    _cmd_search(console, arg)
                elif cmd == "correlate":
                    _cmd_correlate(console)
                elif cmd == "forensic":
                    _cmd_forensic(console)
                elif cmd == "export":
                    _cmd_export(console, arg)
                elif cmd == "demo":
                    _cmd_demo(console)
                elif cmd == "clear":
                    console.clear()
                    _print_banner(console)
                elif cmd == "mode":
                    menu_mode = True
                    console.print()
                    console.print(
                        f"  [{S_SUCCESS}]✓ Switched to MENU mode.[/]"
                    )
                elif cmd in ("h", "help"):
                    _print_help(console)
                else:
                    console.print(
                        f"  [{S_DIM}]Unknown command '{cmd}'. "
                        f"Type 'help' for a list of commands.[/]"
                    )

        except KeyboardInterrupt:
            console.print()
            console.print(f"  [{S_DIM}]Interrupted. Type 'quit' to exit.[/]")
        except Exception as e:
            console.print(f"  [{S_ERROR}]Error:[/] {e}")

    # ── Goodbye ──
    console.print()
    _divider(console, "─")
    console.print(f"  [{S_DIM}]ULPF session ended. Stay safe out there.[/]  [{S_STAR}]★[/]")
    _divider(console, "─")
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC LAUNCHER
# ═══════════════════════════════════════════════════════════════════════════

def launch_tui(mode: str = "auto"):
    """
    Launch the ULPF terminal interface.

    Args:
        mode: Always launches the CLI-style interface.
              The 'mode' parameter is kept for backwards compatibility.
    """
    _setup_windows_utf8()
    _check_dependencies()
    launch_rich_dashboard()


if __name__ == "__main__":
    launch_tui()
