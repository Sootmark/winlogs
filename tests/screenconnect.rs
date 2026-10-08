//! ScreenConnect's client settings and server session database, written
//! for these tests (`tests/fixtures/written/screenconnect/make.py`; no open
//! samples exist), every value compared with what Python's own sqlite3,
//! xml.etree and urllib.parse read (`tests/oracle/screenconnect.tsv`), and
//! the events the generator deleted recovered.

use winlogs::screenconnect::{self, Event, EventSource, SessionDatabase};
use winlogs::Kind;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/written/screenconnect/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A TSV field as the oracle writes it.
fn escaped(field: &str) -> String {
    field
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

fn line(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|field| escaped(field))
        .collect::<Vec<_>>()
        .join("\t")
}

fn time(value: Option<common::time::Ts>) -> Option<String> {
    value.and_then(|t| t.to_iso8601())
}

/// The config files' settings and launch parameters as oracle lines.
fn config_lines() -> Vec<String> {
    let mut lines = Vec::new();
    for name in ["system.config", "user.config"] {
        let config = screenconnect::config(&fixture(name));
        assert_eq!(config.problems, Vec::<String>::new(), "{name}");
        for setting in &config.settings {
            let value = if setting.value.starts_with('<') {
                let tag = setting.value[1..].split([' ', '>']).next().unwrap();
                format!("xml:{tag}")
            } else {
                setting.value.clone()
            };
            lines.push(line(&[
                "config",
                name,
                &setting.section,
                &setting.name,
                &value,
            ]));
        }
        for (key, value) in &config.launch.unwrap().all {
            lines.push(line(&["launch", name, key, value]));
        }
    }
    lines
}

fn event_lines(event: &Event) -> Vec<String> {
    let table = match event.source {
        EventSource::Session => "SessionEvent",
        EventSource::Connection => "SessionConnectionEvent",
    };
    let rowid = event.rowid.unwrap().to_string();
    let event_type = event
        .event_type
        .map(|number| number.to_string())
        .or_else(|| event.event_name.clone());
    [
        ("SessionID", event.session_id.clone()),
        ("ConnectionID", event.connection_id.clone()),
        ("EventID", event.id.clone()),
        ("Time", time(event.time)),
        ("EventType", event_type),
        ("Host", event.host.clone()),
        ("Data", event.data.clone()),
    ]
    .into_iter()
    .filter_map(|(column, value)| Some(line(&["event", table, &rowid, column, &value?])))
    .collect()
}

/// The database's rows as oracle lines.
fn database_lines(db: &SessionDatabase) -> Vec<String> {
    let mut lines = Vec::new();
    for session in &db.sessions {
        let rowid = session.rowid.to_string();
        let mut values = vec![
            ("SessionID".to_owned(), session.id.clone()),
            ("Name".to_owned(), session.name.clone()),
            ("SessionType".to_owned(), session.session_type.clone()),
            ("Host".to_owned(), session.host.clone()),
        ];
        values.extend(
            session
                .custom_properties
                .iter()
                .map(|(column, value)| (column.clone(), Some(value.clone()))),
        );
        for (column, value) in values {
            if let Some(value) = value {
                lines.push(line(&["session", &rowid, &column, &value]));
            }
        }
    }
    for connection in &db.connections {
        let rowid = connection.rowid.to_string();
        for (column, value) in [
            ("SessionID", connection.session_id.clone()),
            ("ConnectionID", connection.id.clone()),
            ("ProcessType", connection.process_type.clone()),
            ("ParticipantName", connection.participant_name.clone()),
            ("NetworkAddress", connection.network_address.clone()),
            ("ClientType", connection.client_type.clone()),
            ("ClientVersion", connection.client_version.clone()),
            ("ConnectedTime", time(connection.connected)),
            ("DisconnectedTime", time(connection.disconnected)),
        ] {
            if let Some(value) = value {
                lines.push(line(&["connection", &rowid, column, &value]));
            }
        }
    }
    lines.extend(db.events.iter().flat_map(event_lines));
    lines
}

#[test]
fn every_value_as_python_reads_it() {
    let db = screenconnect::sessions(&fixture("Session.db"), &[]).unwrap();
    assert_eq!(db.problems, Vec::<String>::new());
    let mut ours = config_lines();
    ours.extend(database_lines(&db));
    let path = format!(
        "{}/tests/oracle/screenconnect.tsv",
        env!("CARGO_MANIFEST_DIR")
    );
    let expected = std::fs::read_to_string(path).unwrap();
    let mut expected: Vec<&str> = expected.lines().collect();
    let mut ours: Vec<&str> = ours.iter().map(String::as_str).collect();
    expected.sort_unstable();
    ours.sort_unstable();
    assert_eq!(ours, expected);
    assert_eq!(ours.len(), 72);
}

#[test]
fn the_launch_parameters_and_event_names() {
    let user = screenconnect::config(&fixture("user.config"));
    let launch = user.launch.unwrap();
    assert_eq!(launch.session_type.as_deref(), Some("Access"));
    assert_eq!(launch.process_type.as_deref(), Some("Guest"));
    assert_eq!(launch.relay_host.as_deref(), Some("relay.example.net"));
    assert_eq!(launch.relay_port.as_deref(), Some("8041"));
    assert_eq!(
        launch.session_id.as_deref(),
        Some("6f1b3c3e-2a4d-4c5e-9f00-1a2b3c4d5e6f")
    );
    assert_eq!(
        launch.custom_properties,
        ["Example Co", "", "Finance laptop"]
    );
    let db = screenconnect::sessions(&fixture("Session.db"), &[]).unwrap();
    let names: Vec<Option<&str>> = db.events.iter().map(|e| e.event_name.as_deref()).collect();
    assert_eq!(
        names,
        [
            Some("QueuedCommand"),
            None,
            Some("CreatedSession"),
            Some("RanCommand"),
            None
        ]
    );
}

/// Whether `event` is the deleted row `expected` (a line of
/// `deleted.tsv`: table, id, time, type, data).
fn is_deleted_row(event: &Event, expected: &str) -> bool {
    let fields: Vec<&str> = expected.split('\t').collect();
    let source = match fields[0] {
        "session" => EventSource::Session,
        _ => EventSource::Connection,
    };
    event.source == source
        && event.id.as_deref() == Some(fields[1])
        && time(event.time) == Some(format!("{}Z", fields[2].replacen(' ', "T", 1)))
        && event.event_type.map(|n| n.to_string()).as_deref() == Some(fields[3])
        && event.data.as_deref() == Some(fields[4])
}

#[test]
fn deleted_events_recovered() {
    let db = screenconnect::sessions(&fixture("Session.db"), &[]).unwrap();
    let deleted = String::from_utf8(fixture("deleted.tsv")).unwrap();
    let deleted: Vec<&str> = deleted.lines().collect();
    for event in &db.deleted_events {
        assert!(
            deleted.iter().any(|row| is_deleted_row(event, row)),
            "recovered an event never deleted: {event:?}"
        );
    }
    let missing: Vec<&&str> = deleted
        .iter()
        .filter(|row| {
            !db.deleted_events
                .iter()
                .any(|event| is_deleted_row(event, row))
        })
        .collect();
    // 241 of 242: a freeblock header overwrote the first bytes of one
    // record, its first column's type with them (a blob's type can't be
    // rebuilt).
    assert_eq!(deleted.len(), 242);
    assert_eq!(
        missing,
        [&"session\taaaaaaaa-0000-4000-8000-000000001094\t2024-01-11 10:34:00.0000000\t44\tdir C:\\Users\\94"]
    );
}

#[test]
fn detection() {
    assert_eq!(
        winlogs::detect(
            r"C:\Program Files (x86)\ScreenConnect\App_Data\Session.db",
            &fixture("Session.db")
        ),
        Some(Kind::ScreenConnectSessions)
    );
    for name in ["system.config", "user.config"] {
        assert_eq!(
            winlogs::detect(name, &fixture(name)),
            Some(Kind::ScreenConnectConfig)
        );
    }
}
