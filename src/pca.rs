//! The Program Compatibility Assistant's logs (Windows 11 22H2 and later,
//! `Windows\appcompat\pca`): evidence of execution that Prefetch may lack.
//!
//! - `PcaAppLaunchDic.txt`: one line per program launched from Explorer,
//!   `path|YYYY-MM-DD HH:MM:SS.fff`, its last launch (UTC).
//! - `PcaGeneralDb0.txt` (and `Db1`): one line per event the assistant
//!   noted: time (UTC), status, path, description, vendor, version, program
//!   identifier, and how the run ended.

use common::time::Ts;

use crate::{date_time, decode, Parsed};

/// A program launched, from `PcaAppLaunchDic.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// Its line, from 1.
    pub line: usize,
    /// The program's path.
    pub program: String,
    /// Its last launch (UTC).
    pub last_run: Ts,
}

/// An event of `PcaGeneralDb0.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its line, from 1.
    pub line: usize,
    /// When (UTC).
    pub time: Ts,
    /// The run status, a number (`2`: an abnormal end).
    pub run_status: String,
    /// The program's path (`%programfiles%\…`, lower case).
    pub program: String,
    /// Its description.
    pub description: String,
    /// Its vendor.
    pub vendor: String,
    /// Its version.
    pub version: String,
    /// The program identifier (as Amcache has it).
    pub program_id: String,
    /// How the run ended (`Abnormal process exit with code 0x4c7`).
    pub exit_code: String,
}

/// Read `PcaAppLaunchDic.txt`.
#[must_use]
pub fn launches(data: &[u8]) -> Parsed<Launch> {
    let mut parsed = Parsed::default();
    for (index, line) in decode(data).lines().enumerate() {
        let line_number = index + 1;
        if line.trim().is_empty() {
            continue;
        }
        let read = line
            .rsplit_once('|')
            .and_then(|(program, time)| Some((program, date_time(time)?.utc()?)));
        match read {
            Some((program, last_run)) if program.contains('\\') => parsed.entries.push(Launch {
                line: line_number,
                program: program.to_owned(),
                last_run,
            }),
            _ => parsed
                .problems
                .push(format!("line {line_number}: not path|time")),
        }
    }
    parsed
}

/// Read `PcaGeneralDb0.txt` or `PcaGeneralDb1.txt`.
#[must_use]
pub fn general(data: &[u8]) -> Parsed<Entry> {
    let mut parsed = Parsed::default();
    for (index, line) in decode(data).lines().enumerate() {
        let line_number = index + 1;
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('|').collect();
        let time = fields.first().and_then(|t| date_time(t)?.utc());
        match (time, fields.as_slice()) {
            (Some(time), [_, status, program, description, vendor, version, id, exit, ..]) => {
                parsed.entries.push(Entry {
                    line: line_number,
                    time,
                    run_status: (*status).to_owned(),
                    program: (*program).to_owned(),
                    description: (*description).to_owned(),
                    vendor: (*vendor).to_owned(),
                    version: (*version).to_owned(),
                    program_id: (*id).to_owned(),
                    exit_code: (*exit).to_owned(),
                });
            }
            _ => parsed.problems.push(format!(
                "line {line_number}: not eight |-separated fields after a time"
            )),
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launches_and_damage() {
        let parsed = launches(b"C:\\x\\a.exe|2022-11-15 00:02:08.476\nbroken\n\n");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].program, "C:\\x\\a.exe");
        assert_eq!(parsed.problems, ["line 2: not path|time"]);
    }

    #[test]
    fn general_entries() {
        let parsed = general(
            b"2022-11-14 23:37:11.789|2|%x%\\a.exe|d|v|1.0|00061|Abnormal exit\n2022-11-14|x\n",
        );
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].exit_code, "Abnormal exit");
        assert_eq!(parsed.problems.len(), 1);
    }
}
