"""
Native Template Miner
=======================
The ULPF-native multi-stage learner.
Pipeline: tokenise → mask → cluster → classify invariant/variable → infer types → map semantics → build ParserSpec

v8.1: Leverages multi-char delimiter detection, enclosure stripping,
      and sub-field KV parsing from the enhanced tokenizer.
"""
from __future__ import annotations

import hashlib
import os

from ulpf.intelligence.auto_parser.miners import TemplateMiner
from ulpf.intelligence.auto_parser.parser_spec import ParserSpec, FieldSpec, MatchSpec
from ulpf.intelligence.auto_parser.tokenizer import tokenise_batch
from ulpf.intelligence.auto_parser.masker import mask_batch, mask_kv_values
from ulpf.intelligence.auto_parser.clusterer import StructuralClusterer, TemplateCluster
from ulpf.intelligence.auto_parser.classifier import classify_positions
from ulpf.intelligence.auto_parser.type_inference import (classify_value, infer_type,
                                                          infer_types_for_positions, is_generalisable)
from ulpf.intelligence.auto_parser.semantic_mapper import _lookup_key, map_fields, infer_family

_WEEKDAYS = frozenset(("mon", "tue", "wed", "thu", "fri", "sat", "sun"))

# Preposition / keyword immediately preceding a value → the key it implies
_IP_TYPES = frozenset(("ipv4", "ipv6", "ipv4_port", "hostname", "domain"))
_CONTEXT_WORDS: dict[str, dict[str, str]] = {
    "from": {t: "src" for t in _IP_TYPES},
    "src": {t: "src" for t in _IP_TYPES},
    "source": {t: "src" for t in _IP_TYPES},
    "client": {t: "src" for t in _IP_TYPES},
    "to": {t: "dst" for t in _IP_TYPES},
    "at": {t: "dst" for t in _IP_TYPES},
    "dst": {t: "dst" for t in _IP_TYPES},
    "destination": {t: "dst" for t in _IP_TYPES},
    "server": {t: "dst" for t in _IP_TYPES},
    "by": {"string": "user"},
    "user": {"string": "user", "hostname": "user"},
    "username": {"string": "user", "hostname": "user"},
    "account": {"string": "user", "hostname": "user"},
    "for": {"string": "user"},
    "port": {"integer": "dst_port", "port": "dst_port"},
    "sport": {"integer": "src_port", "port": "src_port"},
    "dport": {"integer": "dst_port", "port": "dst_port"},
    "pid": {"integer": "pid"},
    "proto": {"string": "proto", "protocol": "proto"},
    "protocol": {"string": "proto", "protocol": "proto"},
    "status": {"string": "status", "action": "status"},
    "action": {"string": "action", "action": "action"},
    "result": {"string": "status", "action": "status"},
}


def _mine_segment(rows: list[list[str]], base_id: int) -> list[dict]:
    """Mine a nested space-separated template from equal-length word lists.

    Returns items: {"k": "lit", "v"} or {"k": "field", "id", "type", "span", "hint"}.
    """
    cls = classify_positions(rows).classifications
    types = [t.best_type for t in infer_types_for_positions(rows)]
    n = len(cls)
    for j, c in enumerate(cls):
        if c.is_invariant and c.invariant_value and is_generalisable(c.invariant_value):
            c.classification, c.invariant_value = "variable", None
    items: list[dict] = []
    j = 0
    while j < n:
        span = 1
        if types[j] == "date" and j + 1 < n and types[j + 1] == "time":
            span, types[j] = 2, "timestamp"
        if cls[j].is_invariant and span == 1:
            items.append({"k": "lit", "v": cls[j].invariant_value})
        else:
            prev = items[-1]["v"] if items and items[-1]["k"] == "lit" else ""
            items.append({"k": "field", "id": base_id + j, "type": types[j], "span": span,
                          "hint": _context_key(prev, types[j]) if prev else None})
        j += span
    return items


def _covers(spec: ParserSpec, lines: list[str], min_ratio: float = 0.9) -> bool:
    """True if the compiled spec parses at least ``min_ratio`` of ``lines``."""
    from ulpf.intelligence.auto_parser.compiler import ParserCompiler
    try:
        parser = ParserCompiler.compile(spec)
    except ValueError:
        return False
    return sum(1 for l in lines if parser.parse(l) is not None) >= min_ratio * len(lines)


def _split_structures(tok_lines: list, min_similarity: float = 0.5) -> list[list[str]]:
    """Group tokenised lines by positional structure.

    A line joins the group whose representative it matches best: the share of
    the representative's constant positions holding the same token (two
    tokens that both contain digits count as the same). Positions where a
    group's members disagree become wildcards, so each group absorbs the
    variable fields of its own format but not a different format.
    """
    groups: list[tuple[list[str | None], list[str]]] = []
    for tl in tok_lines:
        toks = [_unquote(t.stripped_value or t.value) for t in tl.tokens]
        best, best_sim = None, -1.0
        for rep, members in groups:
            if len(rep) != len(toks):
                continue
            const = [(r, t) for r, t in zip(rep, toks) if r is not None]
            same = sum(1 for r, t in const if r == t or (_has_digit(r) and _has_digit(t)))
            sim = same / len(const) if const else 1.0
            if sim > best_sim:
                best, best_sim = (rep, members), sim
        if best is not None and best_sim >= min_similarity:
            rep, members = best
            for k, t in enumerate(toks):
                if rep[k] is not None and rep[k] != t:
                    rep[k] = None
            members.append(tl.raw)
        else:
            groups.append((list(toks), [tl.raw]))
    return [members for _, members in groups]


def _has_digit(token: str) -> bool:
    return any(c.isdigit() for c in token)


def _unquote(value: str) -> str:
    """Drop one layer of surrounding double quotes ("alice" → alice)."""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _context_key(literal: str, value_type: str) -> str | None:
    """Key implied by the literal token preceding a value, if any."""
    word = literal.strip().lower().rstrip(":=").strip()
    if not word:
        return None
    by_type = _CONTEXT_WORDS.get(word)
    if by_type is not None:
        return by_type.get(value_type)
    # "status:" / "user=" style labels that are themselves schema keys
    if literal.rstrip().endswith((":", "=")) and _lookup_key(word):
        return word
    return None


class NativeTemplateMiner(TemplateMiner):
    """ULPF Native Template Miner."""

    def __init__(self, min_cluster_size: int = 5):
        self.min_cluster_size = min_cluster_size
        self.clusterer = StructuralClusterer()
        # parser_id -> (sample lines, line count) of the cluster each spec of
        # the last mine() call was built from
        self.last_clusters: dict[str, tuple[list[str], int]] = {}

    def mine(self, lines: list[str], fingerprint_id: str = "") -> list[ParserSpec]:
        """Mine templates from lines and generate ParserSpecs."""
        if not lines:
            return []

        # 1. Tokenise
        tokenised_lines = tokenise_batch(lines)
        valid_lines = [tl for tl in tokenised_lines if tl.valid]
        if not valid_lines:
            return []

        # 2. Mask
        raw_strings = [tl.raw for tl in valid_lines]
        masked_lines = mask_batch(raw_strings)

        # 3. Cluster
        pairs = [(m.original, m.masked_text) for m in masked_lines]
        clustering_result = self.clusterer.cluster_batch(pairs, fingerprint_id)
        
        # Get stable clusters dynamically scaled to batch size
        eff_min = min(self.min_cluster_size, max(2, len(valid_lines) // 3)) if len(valid_lines) < self.min_cluster_size * 2 else self.min_cluster_size
        clusters = self.clusterer.get_stable_clusters(min_count=eff_min)
        if not clusters and self.clusterer._clusters:
            largest = sorted(self.clusterer._clusters.values(), key=lambda c: c.count, reverse=True)
            if largest:
                clusters = [largest[0]]
        
        specs: list[ParserSpec] = []
        self.last_clusters = {}
        for cluster in clusters:
            spec = self._build_spec_from_cluster(cluster)
            if spec:
                specs.append(spec)
                self.last_clusters[spec.parser_id] = (list(cluster.samples), cluster.count)
        self.clusterer.reset()

        # One fingerprint can be shared by formats that only look alike (same
        # token count, delimiter and value types). If the fingerprint-wide
        # template does not even parse its own lines, mine each structure apart.
        if fingerprint_id and len(clusters) == 1 and not (specs and _covers(specs[0], clusters[0].samples)):
            sub_specs = self._mine_structures(valid_lines, fingerprint_id)
            if sub_specs:
                specs = sub_specs
        return specs

    def _mine_structures(self, tok_lines: list, fingerprint_id: str) -> list[ParserSpec]:
        specs: list[ParserSpec] = []
        clusters: dict[str, tuple[list[str], int]] = {}
        for k, group in enumerate(_split_structures(tok_lines)):
            if len(group) < 2:
                continue
            cluster = TemplateCluster(cluster_id=f"{fingerprint_id}:{k}", template=group[0],
                                      fingerprint=fingerprint_id, samples=group[:100], count=len(group))
            spec = self._build_spec_from_cluster(cluster)
            if spec and _covers(spec, cluster.samples):
                specs.append(spec)
                clusters[spec.parser_id] = (cluster.samples, cluster.count)
        if specs:
            self.last_clusters = clusters
        return specs

    def _build_spec_from_cluster(self, cluster: TemplateCluster) -> ParserSpec | None:
        """Process a single cluster through the rest of the pipeline to produce a ParserSpec."""
        if not cluster.samples:
            return None

        # Re-tokenise the cluster samples to ensure alignment
        tok_lines = tokenise_batch(cluster.samples)
        valid_tok_lines = [tl for tl in tok_lines if tl.valid]

        if not valid_tok_lines:
            return None

        # v8.1: Use enclosure-stripped values for classification so that
        # enclosure characters don't pollute invariant/variable detection.
        # e.g., *INFO* and *WARNING* should be classified as variable "level",
        # not as invariant tokens with different values.
        token_values_list = []
        for tl in valid_tok_lines:
            stripped_vals = []
            for tok in tl.tokens:
                # Prefer the enclosure-stripped, unquoted value for classification
                stripped_vals.append(_unquote(tok.stripped_value if tok.stripped_value else tok.value))
            token_values_list.append(stripped_vals)

        if not token_values_list:
            return None
            
        delimiter = valid_tok_lines[0].delimiter if valid_tok_lines else " "
        kv_format = any(tl.has_kv_pairs for tl in valid_tok_lines)

        # 4. Classify invariant vs variable positions (using stripped values)
        classification = classify_positions(token_values_list)
        cls_list = classification.classifications
        n_pos = len(cls_list)

        # 5. Infer types per position
        types = infer_types_for_positions(token_values_list)
        ptype = [types[p].best_type if p < len(types) else "string" for p in range(n_pos)]

        # 5a. Generalise: a token that is an instance of a variable type (date,
        # time, IP, number, severity, action …) is a field even if every sample
        # happened to share it — otherwise a parser learned today would not
        # match tomorrow's timestamps or a different severity level.
        for pos, cls in enumerate(cls_list):
            if cls.is_invariant and cls.invariant_value and is_generalisable(cls.invariant_value):
                cls.classification = "variable"
                cls.invariant_value = None
                if ptype[pos] == "string":
                    ptype[pos] = classify_value(token_values_list[0][pos])[0].type_name

        # 5b. Multi-token timestamps (space-delimited): "2024-08-28 10:15:30",
        # "Aug 28 10:15:30", "Aug 28 2024 10:15:30" become one timestamp field.
        spans: dict[int, int] = {}
        if delimiter == " ":
            p = 0
            while p < n_pos:
                if ptype[p] == "date" and p + 1 < n_pos and ptype[p + 1] == "time":
                    spans[p] = 2
                elif ptype[p] == "month" and p + 2 < n_pos and ptype[p + 1] == "integer":
                    if ptype[p + 2] == "time":
                        spans[p] = 3
                    elif p + 3 < n_pos and ptype[p + 2] == "integer" and ptype[p + 3] == "time":
                        spans[p] = 4
                p += spans.get(p, 1)
        covered = {s + k for s, ln in spans.items() for k in range(1, ln)}
        for s, ln in spans.items():
            ptype[s] = "timestamp"
            for k in range(ln):
                cls_list[s + k].classification = "variable"
                cls_list[s + k].invariant_value = None

        classification.invariant_positions = [p for p, c in enumerate(cls_list) if c.is_invariant]
        classification.variable_positions = [p for p, c in enumerate(cls_list)
                                             if not c.is_invariant and p not in covered]

        aligned = [tl for tl in valid_tok_lines if len(tl.tokens) == n_pos] or valid_tok_lines
        enclosures: dict[int, tuple[str, str]] = {}
        for i in range(n_pos):
            for tl in aligned:
                enc = tl.tokens[i].enclosure if i < len(tl.tokens) else None
                if enc and "..." in enc:
                    enclosures[i] = tuple(enc.split("...", 1))
                    break

        # 5c. Constant prefix inside an enclosure: "[client 10.0.0.5]" → literal
        # "[client " + an IPv4 field, named from the prefix word.
        prefixes: dict[int, str] = {}
        for pos in range(n_pos):
            if cls_list[pos].is_invariant or pos in covered or pos in spans or pos not in enclosures:
                continue
            vals = [tl.tokens[pos].stripped_value or tl.tokens[pos].value for tl in aligned]
            if ptype[pos] == "timestamp":
                continue
            common = os.path.commonprefix(vals)
            cut = common.rfind(" ")
            # The prefix must be a label ("client "), never data that merely
            # repeated in the sample (a date, a weekday, a number)
            words = common[:cut].split()
            if any(is_generalisable(w) or w[:3].lower() in _WEEKDAYS for w in words):
                continue
            if cut > 0 and all(len(v) > cut + 1 for v in vals):
                prefixes[pos] = common[:cut + 1]
                ptype[pos] = infer_type([v[cut + 1:] for v in vals]).best_type

        # 5d. Free text inside a delimited segment ("User carol logged in from
        # 10.0.0.4") with a consistent word count is mined as a nested template.
        groups: dict[int, list[dict]] = {}
        if delimiter != " ":
            for pos in range(n_pos):
                if cls_list[pos].is_invariant or pos in enclosures or cls_list[pos].classification == "kv_pair":
                    continue
                sub = [(tl.tokens[pos].stripped_value or tl.tokens[pos].value).split() for tl in aligned]
                if len(sub[0]) >= 2 and all(len(s) == len(sub[0]) for s in sub):
                    items = _mine_segment(sub, base_id=1000 * (pos + 1))
                    if len(items) > 1:
                        groups[pos] = items

        # Anchors: literals (top level or nested), KV keys, or a fixed delimiter structure
        n_literals = len(classification.invariant_positions) + sum(
            1 for items in groups.values() for it in items if it["k"] == "lit")
        fixed_shape = delimiter != " " and n_pos >= 3 and len(aligned) == len(valid_tok_lines)
        if not n_literals and not kv_format and len(delimiter) <= 1 and not fixed_shape:
            # Too chaotic, unable to build a reliable template
            return None

        # Prepare positional info for semantic mapping
        pos_info_list = []
        for pos in classification.variable_positions:
            if pos in groups:
                pos_info_list.extend({"position": it["id"], "type": it["type"], "kv_key": it["hint"]}
                                     for it in groups[pos] if it["k"] == "field")
                continue
            c = cls_list[pos]
            # Key hint: explicit key=value key, nested metadata, or the literal
            # word right before the value ("user admin", "from 10.0.0.1")
            sub_kv_key = None
            if c.classification == "kv_pair":
                sub_kv_key = c.kv_key
            else:
                for tl in valid_tok_lines:
                    if pos < len(tl.tokens) and tl.tokens[pos].sub_kv_pairs:
                        sub_kv_key = "metadata"
                        break
                if sub_kv_key is None and pos in prefixes:
                    sub_kv_key = _context_key(prefixes[pos].split()[-1], ptype[pos])
                if sub_kv_key is None and pos > 0 and cls_list[pos - 1].is_invariant:
                    sub_kv_key = _context_key(cls_list[pos - 1].invariant_value or "", ptype[pos])

            pos_info_list.append({"position": pos, "type": ptype[pos], "kv_key": sub_kv_key})

        # Extract all KV pairs from samples for fallback mapping,
        # including sub-KV pairs from nested metadata blocks.
        all_kv_pairs = {}
        for tl in valid_tok_lines:
            if tl.has_kv_pairs:
                all_kv_pairs.update(tl.kv_pairs)
            # v8.1: Also collect sub-KV pairs from individual tokens
            for tok in tl.tokens:
                if tok.sub_kv_pairs:
                    for sk, sv in tok.sub_kv_pairs.items():
                        # Namespace sub-KV keys under "metadata." to avoid
                        # collisions with top-level fields
                        all_kv_pairs[f"metadata.{sk}"] = sv

        # 6. Semantic mapping
        mappings = map_fields(pos_info_list, all_kv_pairs)
        
        # 7. Infer family
        kv_keys = list(all_kv_pairs.keys())
        family, family_conf = infer_family(mappings, kv_keys)

        # 8. Build ParserSpec
        spec = ParserSpec()
        spec.source_family = family
        spec.sample_count = cluster.count

        # Enclosure-aware template (human-readable) plus a machine layout that
        # the compiler turns into a delimiter-aware regex. Field names in the
        # layout are full schema paths (source.ip vs destination.ip).
        names_by_pos = {m.position: m.schema_path for m in mappings if m.position >= 0 and m.schema_path}
        template_tokens = []
        layout: list[dict] = []
        for i, cls in enumerate(classification.classifications):
            if i in covered:
                continue
            if i in spans:
                field_name = names_by_pos.get(i) or "timestamp"
                template_tokens.append(f"{{{field_name.split('.')[-1]}}}")
                layout.append({"k": "field", "v": field_name, "o": "", "c": "", "span": spans[i]})
                continue
            if i in groups:
                items, words = [], []
                for it in groups[i]:
                    if it["k"] == "lit":
                        items.append({"k": "lit", "v": it["v"]})
                        words.append(it["v"])
                    else:
                        name = names_by_pos.get(it["id"]) or f"extensions.field_{i}_{it['id'] % 1000}"
                        items.append({"k": "field", "v": name, "span": it["span"]})
                        words.append(f"{{{name.split('.')[-1]}}}")
                layout.append({"k": "group", "items": items})
                template_tokens.append(" ".join(words))
                continue
            opener, closer = enclosures.get(i, ("", ""))
            opener += prefixes.get(i, "")

            if cls.is_invariant:
                inv_val = cls.invariant_value or ""
                if not opener and not closer:
                    # Classification saw unquoted values; the literal must be the raw text
                    raw = {tl.tokens[i].value for tl in aligned if i < len(tl.tokens)}
                    if len(raw) == 1:
                        inv_val = raw.pop()
                template_tokens.append(f"{opener}{inv_val}{closer}")
                layout.append({"k": "lit", "v": inv_val, "o": opener, "c": closer})
                continue

            field_name = names_by_pos.get(i) or f"extensions.field_{i}"
            if cls.classification == "kv_pair" and cls.kv_key and not opener:
                template_tokens.append(f"{cls.kv_key}=<*>")
                layout.append({"k": "kv", "v": field_name, "key": cls.kv_key})
                continue
            template_tokens.append(f"{opener}{{{field_name.split('.')[-1]}}}{closer}")
            layout.append({"k": "field", "v": field_name, "o": opener, "c": closer})

        spec.template = (f" {delimiter.strip()} ".join(template_tokens) if len(delimiter) > 1
                         else delimiter.join(template_tokens))
        
        # Sample hashes for provenance
        for s in cluster.samples[:5]:
            h = hashlib.sha256(s.encode()).hexdigest()
            if h not in spec.sample_hashes:
                spec.sample_hashes.append(h)

        # Build FieldSpecs — include sub-KV fields as nested fields
        for m in mappings:
            field_spec = FieldSpec(
                name=m.schema_path,
                field_type=m.field_type,
                position=m.position if m.position >= 0 else None,
                original_key=m.original_key or None,
            )
            spec.fields.append(field_spec)

        # v8.1: Add sub-KV fields as additional FieldSpecs
        sub_kv_fields_added = set()
        for tl in valid_tok_lines:
            for tok in tl.tokens:
                if tok.sub_kv_pairs:
                    for sk, sv in tok.sub_kv_pairs.items():
                        namespaced = f"metadata.{sk}"
                        if namespaced not in sub_kv_fields_added:
                            sub_kv_fields_added.add(namespaced)
                            spec.fields.append(FieldSpec(
                                name=namespaced,
                                field_type="string",
                                position=tok.position,
                                original_key=sk,
                            ))

        # Build MatchSpec
        required_tokens = [c.invariant_value for c in classification.classifications 
                          if c.is_invariant and c.invariant_value]
        
        spec.match = MatchSpec(
            required_tokens=required_tokens[:5], # Keep it reasonable
            fingerprint=cluster.fingerprint,
            delimiter=delimiter,
            kv_format=kv_format,
            format_hints={"layout": layout},
        )
        
        # Generate parser ID
        hash_input = f"{family}|{cluster.fingerprint}|{spec.template}"
        spec_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        spec.parser_id = f"auto_{spec_hash}"
        spec.confidence = min(0.95, family_conf + 0.1)

        return spec

