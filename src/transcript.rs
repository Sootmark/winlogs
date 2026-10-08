//! PowerShell transcripts (`Start-Transcript`, or every session when
//! policy turns transcription on: `PowerShell_transcript.<host>.<random>.
//! <time>.txt`): a header (start time, user, run-as user, machine, host
//! program, process, versions) between lines of asterisks, then blocks of
//! what was typed and printed, separated by such lines; a block holding
//! only a time (`Command start time: 20220824123114`) dates the next one.
//!
//! The header's names are localised (`Startzeit:`, `Benutzername:`), so its
//! first seven lines are read by position, as PowerShell writes them; the
//! version lines keep their English names. Times are local, their zone
//! not recorded.

use common::time::Ts;

use crate::{decode, Civil};

/// The line of asterisks between a transcript's parts.
const SEPARATOR: &str = "**********************";
/// The header lines read by position after the start banner.
const POSITIONAL: [&str; 7] = [
    "StartTime",
    "Username",
    "RunAsUser",
    "ConfigurationName",
    "Machine",
    "HostApplication",
    "ProcessId",
];

/// A transcript.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transcript {
    /// When it started (local time).
    pub start: Option<Ts>,
    /// When it ended, if it says (local time).
    pub end: Option<Ts>,
    /// The header's values: the first seven by position (`StartTime`,
    /// `Username`, `RunAsUser`, `ConfigurationName`, `Machine`,
    /// `HostApplication`, `ProcessId`), the rest by their names
    /// (`PSVersion`, `BuildVersion`, …).
    pub header: Vec<(String, String)>,
    /// What was typed and printed, block by block.
    pub blocks: Vec<Block>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

impl Transcript {
    /// A header value by name (`Username`, `Machine`, `PSVersion`).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.header
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A block of a transcript: its lines, and when it began.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Its first line's number, from 1.
    pub line: usize,
    /// When it began: the transcript's start, or the last command start
    /// time before it.
    pub time: Option<Ts>,
    /// Its lines, blank ones left out.
    pub lines: Vec<String>,
}

impl Block {
    /// The commands typed at a prompt (`PS C:\> whoami` gives `whoami`).
    #[must_use]
    pub fn commands(&self) -> Vec<&str> {
        self.lines
            .iter()
            .filter_map(|line| {
                let rest = line.strip_prefix("PS ")?;
                let (_, command) = rest.split_once("> ")?;
                Some(command.trim()).filter(|c| !c.is_empty())
            })
            .collect()
    }
}

/// Read a transcript.
#[must_use]
pub fn read(data: &[u8]) -> Transcript {
    let text = decode(data);
    let lines: Vec<&str> = text.lines().collect();
    let mut transcript = Transcript::default();
    // The parts between separators, with their first line's number.
    let mut parts: Vec<(usize, Vec<&str>)> = Vec::new();
    let mut current: Option<(usize, Vec<&str>)> = None;
    for (index, line) in lines.iter().enumerate() {
        if line.trim_end() == SEPARATOR {
            parts.extend(current.take());
            current = Some((index + 2, Vec::new()));
        } else if let Some((_, part)) = current.as_mut() {
            part.push(line);
        }
    }
    parts.extend(current.filter(|(_, part)| part.iter().any(|l| !l.trim().is_empty())));
    let mut parts = parts.into_iter();
    let Some((_, header)) = parts.next() else {
        transcript
            .problems
            .push("no header between lines of asterisks".to_owned());
        return transcript;
    };
    read_header(&header, &mut transcript);
    let mut time = transcript.start;
    for (line, part) in parts {
        let content: Vec<&str> = part
            .iter()
            .copied()
            .filter(|l| !l.trim().is_empty())
            .collect();
        if let Some(marked) = marker(&content) {
            time = Some(marked);
            if content.iter().any(|l| l.contains("PowerShell")) {
                transcript.end = Some(marked);
            }
            continue;
        }
        if content.is_empty() {
            continue;
        }
        transcript.blocks.push(Block {
            line,
            time,
            lines: content.iter().map(|l| l.trim().to_owned()).collect(),
        });
    }
    transcript
}

/// The header: the start banner, seven values by position, the rest by
/// name.
fn read_header(header: &[&str], transcript: &mut Transcript) {
    let mut values = header
        .iter()
        .skip_while(|l| !l.contains("PowerShell"))
        .skip(1);
    for name in POSITIONAL {
        let Some(line) = values.next() else {
            transcript.problems.push(format!("header: no {name} line"));
            return;
        };
        let value = line.split_once(':').map_or("", |(_, v)| v).trim();
        transcript.header.push((name.to_owned(), value.to_owned()));
    }
    for line in values {
        if let Some((key, value)) = line.split_once(':') {
            transcript
                .header
                .push((key.trim().to_owned(), value.trim().to_owned()));
        }
    }
    transcript.start = transcript.get("StartTime").and_then(compact_time);
}

/// A block holding only a time (`Command start time: …`, or the end banner
/// with `End time: …`): the time.
fn marker(content: &[&str]) -> Option<Ts> {
    let mut time = None;
    for line in content {
        match line
            .rsplit_once(':')
            .and_then(|(_, t)| compact_time(t.trim()))
        {
            Some(found) => time = Some(found),
            None if line.contains("PowerShell") && !line.starts_with("PS ") => {}
            None => return None,
        }
    }
    time
}

/// `YYYYMMDDHHMMSS`, local time.
fn compact_time(text: &str) -> Option<Ts> {
    if text.len() != 14 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let number = |range: std::ops::Range<usize>| text[range].parse::<i64>().ok();
    Civil {
        year: number(0..4)?,
        month: u32::try_from(number(4..6)?).ok()?,
        day: u32::try_from(number(6..8)?).ok()?,
        hour: number(8..10)?,
        minute: number(10..12)?,
        second: number(12..14)?,
        millisecond: 0,
    }
    .local()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGLISH: &str = "**********************\nWindows PowerShell transcript start\nStart time: 20220721023749\nUsername: HOST\\alice\nRunAs User: HOST\\alice\nConfiguration Name:\nMachine: HOST (Microsoft Windows NT 10.0.17763.0)\nHost Application: C:\\x\\powershell.exe\nProcess ID: 6456\nPSVersion: 5.1.17763.1852\n**********************\nPS C:\\> whoami\nhost\\alice\n**********************\nWindows PowerShell transcript end\nEnd time: 20220721023759\n**********************\n";

    #[test]
    fn header_blocks_and_commands() {
        let transcript = read(ENGLISH.as_bytes());
        assert_eq!(transcript.problems, Vec::<String>::new());
        assert_eq!(transcript.get("Username"), Some("HOST\\alice"));
        assert_eq!(transcript.get("PSVersion"), Some("5.1.17763.1852"));
        assert_eq!(transcript.blocks.len(), 1);
        assert_eq!(transcript.blocks[0].commands(), ["whoami"]);
        assert_eq!(
            transcript.end.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2022-07-21T02:37:59.0000000")
        );
    }

    #[test]
    fn not_a_transcript() {
        assert!(!read(b"hello").problems.is_empty());
    }
}
