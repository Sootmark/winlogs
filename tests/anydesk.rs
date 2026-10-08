//! AnyDesk's logs: written for these tests in the formats real lines show
//! (`tests/fixtures/written/`), every line read, the remote IDs, names and
//! addresses found; and real ones from the DFIR Artifact Museum (MIT,
//! `tests/fixtures/museum/`, see its NOTICE), every line read as Python's
//! own `re` reads it (`tests/oracle/anydesk.tsv`, written by
//! `tests/oracle/gen_anydesk.py`).

use winlogs::anydesk;
use winlogs::Kind;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn cell(value: Option<&str>) -> &str {
    value.unwrap_or(r"\N")
}

#[test]
fn real_logs_as_the_oracle_reads_them() {
    let mut got = Vec::new();
    for file in ["museum/ad.trace", "museum/ad_svc.trace"] {
        let data = fixture(file);
        assert_eq!(winlogs::detect(file, &data), Some(Kind::AnyDeskTrace));
        let parsed = anydesk::trace(&data);
        assert_eq!(parsed.problems, Vec::<String>::new());
        got.extend(parsed.entries.iter().map(|e| {
            format!(
                "{file}\t{}\ttrace\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                e.line,
                e.level,
                e.time.to_iso8601().unwrap(),
                e.role,
                e.process,
                e.thread,
                e.module,
                e.message,
                cell(e.remote_id.as_deref()),
                cell(e.remote_name.as_deref()),
                cell(e.address.as_deref())
            )
        }));
    }
    let file = "museum/connection_trace.txt";
    let data = fixture(file);
    assert_eq!(winlogs::detect(file, &data), Some(Kind::AnyDeskConnections));
    let parsed = anydesk::connections(&data);
    assert_eq!(parsed.problems, Vec::<String>::new());
    got.extend(parsed.entries.iter().map(|s| {
        format!(
            "{file}\t{}\tsession\t{}\t{}\t{}\t{}",
            s.line,
            s.direction,
            s.time.to_iso8601().unwrap(),
            s.authorisation,
            s.ids.join(",")
        )
    }));
    let expected: Vec<&str> = include_str!("oracle/anydesk.tsv").lines().collect();
    assert_eq!(got, expected);
}

#[test]
fn a_service_trace() {
    let data = fixture("written/ad_svc.trace");
    assert_eq!(
        winlogs::detect("ProgramData/AnyDesk/ad_svc.trace", &data),
        Some(Kind::AnyDeskTrace)
    );
    assert_eq!(winlogs::detect("copy.log", &data), Some(Kind::AnyDeskTrace));
    let parsed = anydesk::trace(&data);
    assert_eq!(parsed.problems, Vec::<String>::new());
    assert_eq!(parsed.entries.len(), 7);
    let ids: Vec<_> = parsed
        .entries
        .iter()
        .filter_map(|e| e.remote_id.as_deref())
        .collect();
    assert_eq!(ids, ["221436813", "221436813"]);
    assert_eq!(parsed.entries[1].address.as_deref(), Some("198.51.100.4"));
    assert_eq!(
        parsed.entries[3].remote_name.as_deref(),
        Some("Richard Beard")
    );
    assert_eq!(parsed.entries[5].role, "front");
    assert_eq!(parsed.entries[6].level, "warning");
}

#[test]
fn sessions() {
    let data = fixture("written/connection_trace.txt");
    assert_eq!(
        winlogs::detect("connection_trace.txt", &data),
        Some(Kind::AnyDeskConnections)
    );
    assert_eq!(
        winlogs::detect("x.txt", &data),
        Some(Kind::AnyDeskConnections)
    );
    let parsed = anydesk::connections(&data);
    assert_eq!(parsed.problems, Vec::<String>::new());
    let summary: Vec<_> = parsed
        .entries
        .iter()
        .map(|s| {
            (
                s.direction.as_str(),
                s.authorisation.as_str(),
                s.ids[0].as_str(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("Incoming", "User", "221436813"),
            ("Incoming", "Passwd", "904127755"),
            ("Outgoing", "Token", "377110044")
        ]
    );
}
