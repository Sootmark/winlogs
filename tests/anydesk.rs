//! AnyDesk's logs, written for these tests in the formats real lines show
//! (`tests/fixtures/written/`): every line read, the remote IDs, names and
//! addresses found.

use winlogs::anydesk;
use winlogs::Kind;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/written/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn a_service_trace() {
    let data = fixture("ad_svc.trace");
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
    let data = fixture("connection_trace.txt");
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
