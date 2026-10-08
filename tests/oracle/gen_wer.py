"""Writes wer.tsv: the reports in tests/fixtures/written/wer/*/Report.wer
read with Python's own codecs, independently of this crate: one line per
value compared, `folder<TAB>what<TAB>value`.

Run: python3 -I tests/oracle/gen_wer.py tests/fixtures/written/wer > tests/oracle/wer.tsv
"""

import datetime
import pathlib
import re
import sys


def filetime(value):
    moment = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(value) // 10)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}{int(value) % 10}Z"


for folder in sorted(pathlib.Path(sys.argv[1]).iterdir()):
    text = (folder / "Report.wer").read_bytes().decode("utf-16")
    values = [line.split("=", 1) for line in text.splitlines() if "=" in line]
    first = {}
    for name, value in values:
        first.setdefault(name.lower(), value)

    def out(what, value):
        if value is not None:
            print(f"{folder.name}\t{what}\t{value}")

    out("event_type", first.get("eventtype"))
    out("time", filetime(first["eventtime"]) if "eventtime" in first else None)
    out("upload_time", filetime(first["uploadtime"]) if "uploadtime" in first else None)
    out("app_path", first.get("apppath"))
    for prefix, what in (("Sig", "signature"), ("DynamicSig", "dynamic_signature")):
        names = {int(m.group(1)): v for n, v in values for m in [re.fullmatch(prefix + r"\[(\d+)\]\.Name", n)] if m}
        vals = {int(m.group(1)): v for n, v in values for m in [re.fullmatch(prefix + r"\[(\d+)\]\.Value", n)] if m}
        for i in sorted(names):
            out(what, f"{names[i]}={vals.get(i, '')}")
    for name, value in values:
        if name.startswith("LoadedModule["):
            out("module", value)
