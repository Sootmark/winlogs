# winlogs

Windows text logs, for forensics: the plain-text records Windows and common software keep beside the event logs, each read into entries with their time and fields. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-winlogs = "0.2"
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
- `anydesk`: AnyDesk's traces (`ad.trace`, `ad_svc.trace`: every line with its level, time (UTC), process role, module and message; the remote AnyDesk ID, the remote user's name and the address the lines about sessions give) and `connection_trace.txt` (each session's direction, start, authorisation (`User`, `Passwd`, `Token`, `REJECTED`) and IDs).
- `sccm`: Configuration Manager client logs: each entry, multi-line text included, with its component, severity, thread and source file; times in UTC from the log's Windows bias (UTC = local time + bias), local without one.
- Text in UTF-8 or UTF-16 (byte order marks honoured). Local times are kept as local times of unknown zone, never guessed into UTC. Damage goes to `problems`, never a panic.

## How it's checked

- plaso's test logs (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): every one of the 1,356 distinct entries plaso reads from them with its own parsers, read the same (`tests/oracle/`). Beyond plaso, counted in the test: 23 setupapi sections plaso skips, a transcript's last block plaso drops (no separator closes it), an IIS line plaso's grammar rejects, the firewall log's 15 entries (plaso's command line reads none, its own test expects 15), and TeamViewer's repeated lines, which psort keeps once.
- SCCM times are checked apart: plaso applies the bias inconsistently; here UTC = local time + bias, as Windows defines it.
- AnyDesk: no open logs exist; the tests read logs written in the formats real lines published in a CTF write-up show (`tests/fixtures/written/`).
- Property tests: arbitrary text and bytes give entries, problems or nothing, never a panic.

## Licence

MIT or Apache-2.0, at your option.
