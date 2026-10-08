"""Writes screenconnect.tsv: the ScreenConnect samples in
tests/fixtures/written/screenconnect read with Python's own sqlite3,
xml.etree and urllib.parse, independently of this crate. One line per value
compared, tab-separated:

    config      file  section  name  value   (xml:<tag> for a value serialised as XML)
    launch      file  name  value            (the launch parameters, in order)
    session     rowid  column  value
    connection  rowid  column  value
    event       table  rowid  column  value

NULLs are left out; GUID blobs read as .NET writes them; times as
YYYY-MM-DDTHH:MM:SS.fffffffZ; backslashes, tabs and newlines in values
escaped as \\, \t and \n.

Run: python3 -I tests/oracle/gen_screenconnect.py tests/fixtures/written/screenconnect > tests/oracle/screenconnect.tsv
"""

import sqlite3
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qsl

folder = Path(sys.argv[1])


def escaped(field):
    return str(field).replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def out(*fields):
    print("\t".join(escaped(f) for f in fields))


for name in ("system.config", "user.config"):
    root = ET.fromstring(folder.joinpath(name).read_bytes().decode("utf-8-sig"))
    launch = None
    for section in root.iter():
        for setting in section.findall("setting"):
            value = setting.find("value")
            if len(value):
                text = "xml:" + value[0].tag
            else:
                text = value.text or ""
                if launch is None and "?" in text:
                    launch = text.split("?", 1)[1]
            out("config", name, section.tag, setting.get("name"), text)
    for key, value in parse_qsl(launch or "", keep_blank_values=True):
        out("launch", name, key, value)


def text(column, value):
    if isinstance(value, bytes) and len(value) == 16:
        return str(uuid.UUID(bytes_le=value))
    if column in ("Time", "ConnectedTime", "DisconnectedTime"):
        date, _, clock = value.replace("T", " ").partition(" ")
        whole, _, fraction = clock.partition(".")
        return f"{date}T{whole}.{fraction:0<7}Z"
    return str(value)


db = sqlite3.connect(f"file:{folder / 'Session.db'}?mode=ro", uri=True)
db.text_factory = str
COLUMNS = {
    "Session": ["SessionID", "Name", "SessionType", "Host"] + [f"CustomProperty{n}" for n in range(1, 9)],
    "SessionConnection": ["SessionID", "ConnectionID", "ProcessType", "ParticipantName", "NetworkAddress",
                          "ClientType", "ClientVersion", "ConnectedTime", "DisconnectedTime"],
    "SessionEvent": ["SessionID", "ConnectionID", "EventID", "Time", "EventType", "Host", "Data"],
    "SessionConnectionEvent": ["SessionID", "ConnectionID", "EventID", "Time", "EventType", "Data"],
}
KIND = {"Session": ["session"], "SessionConnection": ["connection"],
        "SessionEvent": ["event", "SessionEvent"], "SessionConnectionEvent": ["event", "SessionConnectionEvent"]}
for table, columns in COLUMNS.items():
    for row in db.execute(f"SELECT rowid, {', '.join(columns)} FROM {table} ORDER BY rowid"):
        for column, value in zip(columns, row[1:]):
            if value is None or (column.startswith("CustomProperty") and value == ""):
                continue
            out(*KIND[table], row[0], column, text(column, value))
