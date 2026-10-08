"""Writes anydesk.tsv: AnyDesk's traces and connection_trace.txt read with
Python's own re, independently of this crate: one line per line read,
`\\N` for what it lacks.

- trace lines: file, line number, `trace`, level, time (ISO 8601, UTC),
  role, process, thread, module, message, remote ID, remote name, address;
- sessions: file, line number, `session`, direction, time, authorisation,
  the IDs separated by commas.

Run from tests/fixtures:
python3 -I ../oracle/gen_anydesk.py museum/ad.trace museum/ad_svc.trace \
    museum/connection_trace.txt > ../oracle/anydesk.tsv
"""

import re
import sys

TRACE = re.compile(
    r"\s*(\w+) (\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)\.(\d{3})\s+(\S+)\s+(\d+)\s+(\d+)"
    r"(?:\s+\S+)*?\s+(\S+) - (.*)"
)
SESSION = re.compile(r"(\w+)\s+(\d{4}-\d\d-\d\d), (\d\d:\d\d)\s+(\S+)((?:\s+\S+)*)\s*")
ID = re.compile(r"\d+|\S+@\S+")


def remote(message):
    """The remote name and ID a message gives."""
    m = re.fullmatch(r"Incoming session request: (.*) \((\S+)\)", message)
    if m:
        return m.group(1), m.group(2) if ID.fullmatch(m.group(2)) else None
    m = re.match(r"Client-ID: (\S+) \(FPR: ", message)
    if m:
        return None, m.group(1) if ID.fullmatch(m.group(1)) else None
    m = re.search(r"(?:Accept request from|Accepting from) ([^ .,]*)", message)
    if m:
        return None, m.group(1) if ID.fullmatch(m.group(1)) else None
    return None, None


def address(message):
    m = re.search(r"Logged in from (\S+)", message)
    if not m:
        return None
    ip = m.group(1).rsplit(":", 1)[0]
    return ip.strip("[]") if re.search(r"\d", ip) else None


def cell(value):
    return "\\N" if value is None else value


for name in sys.argv[1:]:
    text = open(name, encoding="utf-8").read()
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = TRACE.fullmatch(line.rstrip())
        if m:
            level, date, clock, millis, role, pid, tid, module, message = m.groups()
            message = message.strip()
            remote_name, remote_id = remote(message)
            time = f"{date}T{clock}.{millis}0000Z"
            cells = [level, time, role, pid, tid, module, message, remote_id, remote_name, address(message)]
            print("\t".join([name, str(number), "trace"] + [cell(c) for c in cells]))
            continue
        m = SESSION.fullmatch(line)
        if m:
            direction, date, clock, authorisation, ids = m.groups()
            time = f"{date}T{clock}:00.0000000Z"
            cells = [direction, time, authorisation, ",".join(ids.split())]
            print("\t".join([name, str(number), "session"] + cells))
            continue
        print("\t".join([name, str(number), "unread"]))
