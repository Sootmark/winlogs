//! W3C extended logs: directives (`#Software:`, `#Date:`, `#Fields:`,
//! `#Time Format:`) then one line per entry, its values separated by
//! blanks in the order the last `#Fields:` gave. IIS writes them
//! (`inetpub\logs\LogFiles\W3SVC*\u_ex*.log`, times in UTC), and so does the
//! Windows Firewall (`pfirewall.log`, `#Time Format: Local`).

use common::time::Ts;

use crate::{civil, date_ymd, decode, time_hms};

/// What wrote a log, from its `#Software:` directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// Internet Information Services.
    Iis,
    /// The Windows Firewall.
    Firewall,
    /// Another program.
    Other,
}

/// A W3C log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    /// What wrote it.
    pub source: Source,
    /// The `#Software:` directive, as written.
    pub software: Option<String>,
    /// The entries.
    pub entries: Vec<Entry>,
    /// Lines that couldn't be read.
    pub problems: Vec<String>,
}

/// An entry: its time and its values by field name (`-`, the empty value,
/// left out).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its line, from 1.
    pub line: usize,
    /// When: UTC, or the wall clock of an unknown zone when the log says
    /// `#Time Format: Local`.
    pub time: Option<Ts>,
    /// The values, by field name (`c-ip`, `cs-uri-stem`, `src-ip`, …), in
    /// the order the log gives them.
    pub fields: Vec<(String, String)>,
}

impl Entry {
    /// The value of field `name`, if set.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Read a W3C log.
#[must_use]
pub fn read(data: &[u8]) -> Log {
    let mut log = Log {
        source: Source::Other,
        software: None,
        entries: Vec::new(),
        problems: Vec::new(),
    };
    let mut fields: Vec<String> = Vec::new();
    let mut header_date = None;
    let mut local = false;
    for (index, line) in decode(data).lines().enumerate() {
        let line_number = index + 1;
        let line = line.trim_end();
        if let Some(directive) = line.strip_prefix('#') {
            let (name, value) = directive.split_once(':').unwrap_or((directive, ""));
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "fields" => fields = value.split_whitespace().map(str::to_owned).collect(),
                "software" => {
                    log.source = if value.contains("Internet Information Services") {
                        Source::Iis
                    } else if value.contains("Windows Firewall") {
                        Source::Firewall
                    } else {
                        Source::Other
                    };
                    log.software = Some(value.to_owned());
                }
                "date" => header_date = value.split_whitespace().next().and_then(date_ymd),
                "time format" => local = value.eq_ignore_ascii_case("local"),
                _ => {}
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        let values: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() || values.len() != fields.len() {
            log.problems.push(format!(
                "line {line_number}: {} values for {} fields",
                values.len(),
                fields.len()
            ));
            continue;
        }
        let column = |name: &str| fields.iter().position(|f| f == name).map(|at| values[at]);
        let day = column("date").and_then(date_ymd).or(header_date);
        let clock = column("time").and_then(time_hms);
        let time = day.zip(clock).and_then(|(day, clock)| {
            let when = civil(day, clock);
            if local {
                when.local()
            } else {
                when.utc()
            }
        });
        log.entries.push(Entry {
            line: line_number,
            time,
            fields: fields
                .iter()
                .zip(&values)
                .filter(|(name, value)| **value != "-" && *name != "date" && *name != "time")
                .map(|(name, value)| (name.clone(), (*value).to_owned()))
                .collect(),
        });
    }
    log
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iis_with_and_without_dates() {
        let log = read(b"#Software: Microsoft Internet Information Services 6.0\n#Date: 2013-07-30 00:00:00\n#Fields: time c-ip cs-method cs-uri-stem sc-status\n00:00:03 22.22.22.200 GET /a.aspx 404\n00:00:04 22.22.22.200 GET\n");
        assert_eq!(log.source, Source::Iis);
        assert_eq!(log.entries.len(), 1);
        let entry = &log.entries[0];
        assert_eq!(entry.get("c-ip"), Some("22.22.22.200"));
        assert_eq!(
            entry.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2013-07-30T00:00:03.0000000Z")
        );
        assert_eq!(log.problems, ["line 5: 3 values for 5 fields"]);
    }

    #[test]
    fn the_firewall_in_local_time() {
        let log = read(b"#Software: Microsoft Windows Firewall\n#Time Format: Local\n#Fields: date time action src-ip info\n2005-04-11 08:05:57 DROP 1.2.3.4 -\n");
        assert_eq!(log.source, Source::Firewall);
        let entry = &log.entries[0];
        assert_eq!(entry.get("action"), Some("DROP"));
        assert_eq!(entry.get("info"), None);
        assert_eq!(
            entry.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2005-04-11T08:05:57.0000000")
        );
    }
}
