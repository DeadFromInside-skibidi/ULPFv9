"""
Identity resolution: account identifiers from different systems -> one canonical Actor.

Identifiers are parsed into (kind, local name, realm):

* Active Directory ``CORP\\jdoe`` (NetBIOS realm), UPN / e-mail ``jdoe@corp.com``,
  Kerberos ``jdoe@CORP.COM``, LDAP DN ``CN=jdoe,OU=..,DC=corp,DC=com``;
* AWS IAM ``arn:aws:iam::123456789012:user/jdoe``, STS ``arn:aws:sts::..:assumed-role/Role/jdoe``;
* Okta / Entra logins (e-mail), Linux ``uid=1000(jdoe)`` and bare names.

Identifiers join one actor when

1. a directory import says so (``import_directory``: canonical id, aliases, attributes);
2. one event carries several of them (user.name, user.email, user.id, source / target user);
3. their local names are equal and their realms are one organisation (``realm_aliases``:
   CORP = corp.com = CORP.COM), or one side has no realm and the name is known in only one
   organisation.

Generic names (root, administrator, system, guest, ...) never join by name alone, so ``root``
on two hosts stays two actors. Actor ids are the smallest identifier key of the group, so they
are stable and deterministic.

SQLite (``identities``) is the source of truth; memory holds a bounded LRU of recently seen
identifiers. New identifiers and merges are written at once (rare); last-seen times are
written behind.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass

from ulpf.ueba.store import LRU, Store, dumps

GENERIC_NAMES = frozenset({"root", "admin", "administrator", "system", "guest", "nobody", "daemon", "service",
                           "localsystem", "networkservice", "localservice", "anonymous", "sa", "test", "user",
                           "ec2-user", "ubuntu", "postgres", "www-data", "unknown"})
_ARN = re.compile(r"^arn:aws[\w-]*:(iam|sts)::(\d*):(user|role|assumed-role|federated-user)/(.+)$")
_DN_CN = re.compile(r"(?i)\bCN=([^,]+)")
_DN_DC = re.compile(r"(?i)\bDC=([^,]+)")
_UID = re.compile(r"^uid=(\d+)(?:\((.+)\))?$")


@dataclass(frozen=True)
class Ident:
    kind: str       # ad, upn, kerberos, dn, aws_user, aws_role, linux, plain
    name: str       # local name, lower case
    realm: str      # realm, lower case ("" none)
    raw: str

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.realm}:{self.name}"


def parse_identity(raw) -> Ident | None:
    """One account identifier in any supported form (None: empty or not an identity)."""
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or s.lower() in ("-", "n/a", "unknown", "none", "null") or len(s) > 512:
        return None
    m = _ARN.match(s)
    if m:
        _svc, acct, typ, rest = m.groups()
        if typ == "assumed-role":                  # assumed-role/Role/session: the session is the person
            return Ident("aws_role", rest.split("/")[-1].lower(), acct, s)
        return Ident("aws_user" if typ == "user" else "aws_role", rest.split("/")[-1].lower(), acct, s)
    if "=" in s and _DN_CN.search(s):
        cn = _DN_CN.search(s).group(1).strip().lower()
        return Ident("dn", cn, ".".join(x.lower() for x in _DN_DC.findall(s)), s)
    m = _UID.match(s)
    if m:
        return Ident("linux", (m.group(2) or m.group(1)).lower(), "", s)
    if "\\" in s:
        dom, _, name = s.partition("\\")
        if name:
            return Ident("ad", name.lower(), dom.lower(), s)
    if "@" in s:
        name, _, dom = s.rpartition("@")
        if name and dom:
            return Ident("kerberos" if dom.isupper() and "." in dom else "upn", name.lower(), dom.lower(), s)
    return Ident("plain", s.lower(), "", s)


class IdentityGraph:
    def __init__(self, store: Store, realm_aliases: list | None = None, cache: int = 100_000):
        self.store = store
        self.realm_of: dict[str, str] = {}
        for group in realm_aliases or []:
            org = str(group[0]).lower()
            for r in group:
                self.realm_of[str(r).lower()] = org
        self.cache = LRU(cache, self._evicted)     # ident key -> actor
        self.members: dict[str, set] = {}          # actor -> cached ident keys (for merges)
        self.attrs = LRU(max(1000, cache // 4))    # actor -> attributes
        self.stats = {"identities": 0, "merges": 0}
        store.db.execute("""CREATE TABLE IF NOT EXISTS ident_names (ident TEXT PRIMARY KEY, name TEXT, org TEXT)""")
        store.db.execute("CREATE INDEX IF NOT EXISTS ident_names_name ON ident_names(name, org)")

    def _org(self, realm: str) -> str:
        if not realm:
            return ""
        r = realm.lower()
        return self.realm_of.get(r) or self.realm_of.get(r.split(".")[0]) or r

    def _evicted(self, key, actor) -> None:
        s = self.members.get(actor)
        if s is not None:
            s.discard(key)
            if not s:
                del self.members[actor]

    def _cache(self, key: str, actor: str) -> None:
        old = self.cache.get(key)
        if old is not None and old != actor:
            self._evicted(key, old)
        self.cache.put(key, actor)
        self.members.setdefault(actor, set()).add(key)

    def actor_of(self, key: str) -> str | None:
        a = self.cache.get(key)
        if a is not None:
            return a
        row = self.store.one("SELECT actor FROM identities WHERE ident = ?", (key,))
        if row:
            self._cache(key, row[0])
            return row[0]
        return None

    def _new(self, ident: Ident, now: float) -> str:
        """Record a first-seen identifier; returns its actor (after name linking)."""
        key = ident.key
        org = self._org(ident.realm)
        with self.store.lock:
            self.store.db.execute("INSERT OR IGNORE INTO identities VALUES (?, ?, ?, ?, ?)",
                                  (key, key, ident.kind, now, now))
            self.store.db.execute("INSERT OR IGNORE INTO ident_names VALUES (?, ?, ?)", (key, ident.name, org))
        self.stats["identities"] += 1
        actor = key
        self._cache(key, actor)
        if ident.name in GENERIC_NAMES:
            return actor
        rows = self.store.all("SELECT n.ident, n.org, i.actor FROM ident_names n JOIN identities i USING (ident) "
                              "WHERE n.name = ? AND n.ident <> ?", (ident.name, key))
        if org:
            same = [r for r in rows if r[1] == org]
            for r in rows:                          # a realm-less name, unless its actor is another organisation's
                if not r[1] and not self.store.one(
                        "SELECT 1 FROM ident_names n JOIN identities i USING (ident) WHERE i.actor = ? AND n.org <> '' "
                        "AND n.org <> ? LIMIT 1", (r[2], org)):
                    same.append(r)
        else:                                       # no realm: join only if the name has one organisation
            orgs = {r[1] for r in rows if r[1]}
            same = rows if len(orgs) <= 1 else [r for r in rows if not r[1]]
        for _other, _o, other_actor in same:
            actor = self._merge(actor, other_actor)
        return actor

    def _merge(self, a: str, b: str) -> str:
        if a == b:
            return a
        root, drop = (a, b) if a < b else (b, a)
        with self.store.lock:
            self.store.db.execute("UPDATE identities SET actor = ? WHERE actor = ?", (root, drop))
        for key in list(self.members.pop(drop, ())):
            self.cache.put(key, root)
            self.members.setdefault(root, set()).add(key)
        attrs = {**self.attributes(drop), **self.attributes(root)}
        if attrs:
            self._set_attrs(root, attrs)
        self.stats["merges"] += 1
        return root

    def resolve(self, identifiers, now: float | None = None) -> str | None:
        """The canonical actor of these co-occurring identifiers (they are linked together)."""
        now = now or time.time()
        idents = []
        seen = set()
        for x in identifiers:
            i = parse_identity(x)
            if i is not None and i.key not in seen:
                seen.add(i.key)
                idents.append(i)
        if not idents:
            return None
        actor = None
        for i in idents:
            a = self.actor_of(i.key)
            if a is None:
                a = self._new(i, now)
            else:
                self.store.queue("UPDATE identities SET last_seen = ? WHERE ident = ?", (now, i.key))
            if actor is None:
                actor = a
            elif a != actor and not (idents[0].name in GENERIC_NAMES and i.name in GENERIC_NAMES):
                actor = self._merge(actor, a)
        return actor

    def aliases(self, actor: str) -> list[str]:
        return [r[0] for r in self.store.all("SELECT ident FROM identities WHERE actor = ? ORDER BY ident", (actor,))]

    def count(self) -> tuple[int, int]:
        n = self.store.one("SELECT count(*), count(DISTINCT actor) FROM identities")
        return n[0], n[1]

    # ---- attributes (department, title, role, display name, manager ...)
    def attributes(self, actor: str) -> dict:
        v = self.attrs.get(actor)
        if v is None:
            row = self.store.one("SELECT doc FROM actors WHERE actor = ?", (actor,))
            v = json.loads(row[0]) if row else {}
            self.attrs.put(actor, v)
        return v

    def _set_attrs(self, actor: str, doc: dict) -> None:
        self.attrs.put(actor, doc)
        with self.store.lock:
            self.store.db.execute("INSERT OR REPLACE INTO actors VALUES (?, ?)", (actor, dumps(doc)))

    def import_directory(self, rows: list[dict]) -> int:
        """Directory rows {"id": canonical identifier, "aliases": [...], "department", "title",
        "role", "display_name", "manager", ...}: every alias joins the row's actor."""
        n = 0
        for row in rows:
            ids = [x for x in [row.get("id")] + list(row.get("aliases") or []) if x]
            idents = [i for i in map(parse_identity, ids) if i]
            if not idents:
                continue
            actor = None
            for i in idents:
                a = self.actor_of(i.key) or self._new(i, time.time())
                actor = a if actor is None else self._merge(actor, a)
            attrs = {k: v for k, v in row.items() if k not in ("id", "aliases") and v not in (None, "")}
            self._set_attrs(actor, {**self.attributes(actor), **attrs})
            n += 1
        return n
