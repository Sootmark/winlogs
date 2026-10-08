# winlogs

Windows text logs, for forensics: the plain-text records Windows and common software keep beside the event logs, each read into entries with their time and fields; and the settings and session database of ConnectWise ScreenConnect. Two dependencies, its siblings `sootmark-common` (times) and `sootmark-sqlite` (ScreenConnect's `Session.db`).

```toml
[dependencies]
sootmark-winlogs = "0.4"
```

```rust
let data = std::fs::read(r"C:\Windows\appcompat\pca\PcaAppLaunchDic.txt")?;
for launch in winlogs::pca::launches(&data).entries {
    println!("{} last run {:?}", launch.program, launch.last_run);
}
```

## What you get

- `detect(name, head)`: which log a file is, by name and content.
- `pca`: the Program Compatibility Assistant (Windows 11 22H2 and later, `Windows\appcompat\pca`): `PcaAppLaunchDic.txt`, each program launched and its last launch (UTC); `PcaGeneralDb0.txt`/`Db1`, each event with its status, path, description, vendor, version, program identifier and exit. Evidence of execution Prefetch may not have.
- `w3c`: W3C extended logs, any fields, directives followed (`#Fields:` changes mid-file, `#Date:` for logs without a date column, `#Time Format: Local`): IIS (`u_ex*.log`, UTC: the requests a web shell leaves) and the Windows Firewall (`pfirewall.log`, local time), with the writer named from `#Software:`.
- `transcript`: PowerShell transcripts: the header (user, run-as user, machine, host program, process, versions; localised names read by position), the end time, and each block of what was typed and printed with its time and the commands typed at a prompt.
- `teamviewer`: TeamViewer's application log (multi-line entries joined) and its connection lists, in (`Connections_incoming.txt`: remote ID and name, start, end, local account, kind, session) and out (`Connections.txt`).
- `setupapi`: SetupAPI's logs (`setupapi.dev.log`, …): each section's title (a USB drive's first install), start, end and exit status.
- `anydesk`: AnyDesk's traces (`ad.trace`, `ad_svc.trace`: every line with its level, time (UTC), process role, module and message; the remote AnyDesk ID (a session request, an accepted request, a connecting peer's `Client-ID`), the remote user's name and the address the lines about sessions give) and `connection_trace.txt` (each session's direction, start, authorisation (`User`, `Passwd`, `Token`, `REJECTED`) and IDs).
- `sccm`: Configuration Manager client logs: each entry, multi-line text included, with its component, severity, thread and source file; times in UTC from the log's Windows bias (UTC = local time + bias), local without one.
- `wer`: Windows Error Reporting's reports (`Report.wer`, `WER\ReportArchive` and `ReportQueue`, the system's and each user's): the event type (`APPCRASH`, `BEX64`, `AppHangB1`, …), when it happened and was reported (UTC), the program's name and path, the signature (application, version, faulting module, exception code, offset), the dynamic signature, the modules loaded, and every value. Evidence of execution, and of tools that crashed doing their work.
- `screenconnect`: ConnectWise ScreenConnect (formerly ConnectWise Control), remote access often abused:
  - `config`: the client's `system.config` (`Program Files (x86)\ScreenConnect Client (<thumbprint>)`) and `user.config` (a user's `AppData\Local\ScreenConnect Client (<thumbprint>)`): every .NET setting (section, name, value), and the launch parameters they hold: session type (`e`), process type (`y`), relay host (`h`) and port (`p`), session id (`s`), key (`k`), custom properties (`c`) and every other parameter, form-decoded. `launch_parameters` reads the same from the client service's `ImagePath`;
  - `sessions`: the server's `App_Data\Session.db` (SQLite, with its `-wal`): sessions (id, name, type, host, custom properties), connections (session, participant, process type host or guest, network address, client type and version, connected and disconnected times) and events of sessions and connections (time, type, host, data: commands queued and their output, files transferred, messages), and events deleted (a maintenance purge, a cleanup by hand) recovered from free space with `sootmark-sqlite`. Event types 44 and 70 are named `QueuedCommand` and `RanCommand`, the meaning ImmyBot's integration guide gives them; other numbers are kept as numbers.
  - ScreenConnect's own `*.log` files (server and toolbox) have no documented format and aren't read; its Application event log entries are read with the event logs.
- Text in UTF-8 or UTF-16 (byte order marks honoured). Local times are kept as local times of unknown zone, never guessed into UTC. Damage goes to `problems`, never a panic.

## How it's checked

- plaso's test logs (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): every one of the 1,356 distinct entries plaso reads from them with its own parsers, read the same (`tests/oracle/`). Beyond plaso, counted in the test: 23 setupapi sections plaso skips, a transcript's last block plaso drops (no separator closes it), an IIS line plaso's grammar rejects, the firewall log's 15 entries (plaso's command line reads none, its own test expects 15), and TeamViewer's repeated lines, which psort keeps once.
- SCCM times are checked apart: plaso applies the bias inconsistently; here UTC = local time + bias, as Windows defines it.
- AnyDesk: the DFIR Artifact Museum's `ad.trace`, `ad_svc.trace` and `connection_trace.txt` (MIT, `tests/fixtures/museum/`): all 16 trace lines and 2 sessions read as Python's own `re` reads them (`tests/oracle/anydesk.tsv`), the remote IDs of `Client-ID: <id> (FPR: …)` lines matching the sessions' IDs; and logs written in the formats real lines published in a CTF write-up show (`tests/fixtures/written/`).
- Windows Error Reporting: no open reports exist; reports written as Windows writes them (`tests/fixtures/written/wer/`), every value compared with what Python's own codecs read (`tests/oracle/gen_wer.py`, `wer.tsv`).
- ScreenConnect: no open samples exist, and ConnectWise doesn't document `Session.db`. The files in `tests/fixtures/written/screenconnect/` are written by `make.py` (the settings layout public scripts read from real clients; the database's tables and columns as ScreenConnect's reports name them, with assumed column types, some values in the other type SQLite allows): every value read as Python's own sqlite3, xml.etree and urllib.parse read it (`tests/oracle/gen_screenconnect.py`, `screenconnect.tsv`: 72 values), and 241 of the 242 events a purge and two deletions removed recovered (the last lost its first bytes to a freeblock header). **Unverified**: the column types, time format and time zone (UTC assumed) of a real `Session.db`, the numbers of event and process types other than 44 and 70, and the names of the settings, until an openly licensed sample is found.
- Property tests: arbitrary text and bytes, markup, and the session database damaged or cut give entries, problems or nothing, never a panic.

## Licence

MIT or Apache-2.0, at your option.
