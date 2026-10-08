//! The ScreenConnect server's session database, `App_Data\Session.db`
//! (SQLite, with its `-wal` file): tables `Session`, `SessionConnection`,
//! `SessionEvent` and `SessionConnectionEvent`.
//!
//! ConnectWise doesn't document the database. Columns are read by the
//! names ScreenConnect's reports and session manager give these fields
//! (`SessionID`, `ConnectionID`, `ProcessType`, `ParticipantName`,
//! `NetworkAddress`, `ConnectedTime`, `EventType`, `Time`, `Data`, …), a
//! column a version lacks reading as nothing; values in whichever type
//! SQLite holds them: GUIDs as 16 bytes (.NET's layout) or text, times as
//! text (`YYYY-MM-DD HH:MM:SS[.fffffff]`, UTC, as ScreenConnect's own
//! maintenance queries compare them with SQLite's `DATETIME('now')`).

use common::time::{Precision, Ts};
use common::win::guid_to_string;
use sqlite::{Database, RecoveredRecord, Value};

/// The tables.
const SESSIONS: &str = "Session";
const CONNECTIONS: &str = "SessionConnection";
const SESSION_EVENTS: &str = "SessionEvent";
const CONNECTION_EVENTS: &str = "SessionConnectionEvent";
/// The custom property columns, `CustomProperty1` to this.
const CUSTOM_PROPERTIES: usize = 8;
/// Event types with a published meaning (ImmyBot's ScreenConnect
/// integration guide: commands are queued as 44 in `SessionEvent`, their
/// output is 70 in `SessionConnectionEvent`).
const EVENT_NAMES: [(i64, &str); 2] = [(44, "QueuedCommand"), (70, "RanCommand")];
/// Bytes of a GUID.
const GUID_SIZE: usize = 16;

/// A session (a machine reached, a support session, a meeting).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    /// Its rowid.
    pub rowid: i64,
    /// `SessionID`.
    pub id: Option<String>,
    /// `Name`: the machine or the session's name.
    pub name: Option<String>,
    /// `SessionType`, as stored (`Access`, `Support`, `Meeting`, or a
    /// number).
    pub session_type: Option<String>,
    /// `Host`: the technician who owns it.
    pub host: Option<String>,
    /// `CustomProperty1` to `8` that hold a value: (column, value).
    pub custom_properties: Vec<(String, String)>,
}

/// A connection to a session: a host (technician) or guest (the machine)
/// joining it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Connection {
    /// Its rowid.
    pub rowid: i64,
    /// `SessionID`.
    pub session_id: Option<String>,
    /// `ConnectionID`.
    pub id: Option<String>,
    /// `ProcessType`, as stored (`Host`, `Guest`, or a number).
    pub process_type: Option<String>,
    /// `ParticipantName`: who connected.
    pub participant_name: Option<String>,
    /// `NetworkAddress`: where from.
    pub network_address: Option<String>,
    /// `ClientType`.
    pub client_type: Option<String>,
    /// `ClientVersion`.
    pub client_version: Option<String>,
    /// `ConnectedTime` (UTC).
    pub connected: Option<Ts>,
    /// `DisconnectedTime` (UTC).
    pub disconnected: Option<Ts>,
}

/// Which table an event is from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventSource {
    /// `SessionEvent`: the session's (a command queued, a note).
    Session,
    /// `SessionConnectionEvent`: a connection's (a command's output, a
    /// file transferred, a message sent).
    Connection,
}

/// An event of a session or of one of its connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Its table.
    pub source: EventSource,
    /// Its rowid (`None` for a deleted event whose cell start is lost).
    pub rowid: Option<i64>,
    /// `SessionID`.
    pub session_id: Option<String>,
    /// `ConnectionID` (connection events).
    pub connection_id: Option<String>,
    /// `EventID`.
    pub id: Option<String>,
    /// `Time` (UTC).
    pub time: Option<Ts>,
    /// `EventType`, when stored as a number.
    pub event_type: Option<i64>,
    /// The event type's name: as stored when text, else the published name
    /// of its number (`QueuedCommand` 44, `RanCommand` 70).
    pub event_name: Option<String>,
    /// `Host`: the technician behind it.
    pub host: Option<String>,
    /// `Data`: the command and its output, the file, the message.
    pub data: Option<String>,
}

/// What a session database holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionDatabase {
    /// The `Session` rows.
    pub sessions: Vec<Session>,
    /// The `SessionConnection` rows.
    pub connections: Vec<Connection>,
    /// The `SessionEvent` then `SessionConnectionEvent` rows.
    pub events: Vec<Event>,
    /// Events deleted (purged by maintenance or by hand) whose records
    /// SQLite left in free space or older pages of the log; their values
    /// as far as they survive.
    pub deleted_events: Vec<Event>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The sessions, connections and events of `Session.db`, with its `-wal`
/// file's committed changes (`wal` empty without one).
///
/// # Errors
/// When the file isn't a SQLite database.
pub fn sessions(database: &[u8], wal: &[u8]) -> Result<SessionDatabase, sqlite::Error> {
    let db = Database::open_with_wal(database, wal)?;
    let mut read = SessionDatabase {
        problems: db.problems.clone(),
        ..SessionDatabase::default()
    };
    if [SESSIONS, CONNECTIONS, SESSION_EVENTS, CONNECTION_EVENTS]
        .iter()
        .all(|table| db.table(table).is_none())
    {
        read.problems
            .push("none of ScreenConnect's session tables".to_owned());
        return Ok(read);
    }
    read.sessions = rows(&db, SESSIONS, &mut read.problems, session);
    read.connections = rows(&db, CONNECTIONS, &mut read.problems, connection);
    read.events = rows(&db, SESSION_EVENTS, &mut read.problems, |row, problems| {
        event(row, EventSource::Session, problems)
    });
    read.events.extend(rows(
        &db,
        CONNECTION_EVENTS,
        &mut read.problems,
        |row, problems| event(row, EventSource::Connection, problems),
    ));
    read.deleted_events = deleted_events(&db, &mut read.problems);
    Ok(read)
}

/// A row's values with its table's column names.
struct Named<'r> {
    table: &'r str,
    columns: &'r [String],
    rowid: Option<i64>,
    values: Vec<Option<&'r Value>>,
}

impl Named<'_> {
    fn value(&self, column: &str) -> Option<&Value> {
        let at = self
            .columns
            .iter()
            .position(|name| name.eq_ignore_ascii_case(column))?;
        self.values.get(at).copied().flatten()
    }

    /// Text as stored, a number in decimal; `None` for NULL or a blob.
    fn text(&self, column: &str) -> Option<String> {
        match self.value(column)? {
            Value::Text(text) => Some(text.clone()),
            Value::Integer(number) => Some(number.to_string()),
            Value::Real(number) => Some(number.to_string()),
            Value::Null | Value::Blob(_) => None,
        }
    }

    /// A GUID: 16 bytes in .NET's layout, or text.
    fn guid(&self, column: &str, problems: &mut Vec<String>) -> Option<String> {
        match self.value(column)? {
            Value::Blob(bytes) => {
                let guid = <[u8; GUID_SIZE]>::try_from(bytes.as_slice()).ok();
                if guid.is_none() {
                    self.problem(
                        column,
                        &format!("a {}-byte blob, not a GUID", bytes.len()),
                        problems,
                    );
                }
                guid.map(|bytes| guid_to_string(&bytes))
            }
            Value::Text(text) => Some(text.clone()),
            _ => self.text(column),
        }
    }

    /// A time stored as text, UTC.
    fn time(&self, column: &str, problems: &mut Vec<String>) -> Option<Ts> {
        let value = self.value(column)?;
        let time = match value {
            Value::Text(text) => parse_time(text),
            Value::Null => return None,
            _ => None,
        };
        if time.is_none() {
            self.problem(
                column,
                &format!("{value:?} is not a date and time"),
                problems,
            );
        }
        time
    }

    fn problem(&self, column: &str, what: &str, problems: &mut Vec<String>) {
        let row = self
            .rowid
            .map_or_else(|| "a deleted row".to_owned(), |r| format!("row {r}"));
        problems.push(format!("{}: {row}'s {column}: {what}", self.table));
    }
}

/// `YYYY-MM-DD HH:MM:SS[.fffffff]` (or with `T`, or a trailing `Z`), UTC;
/// to the second without a fraction.
fn parse_time(text: &str) -> Option<Ts> {
    let trimmed = text.trim().trim_end_matches('Z');
    let iso = format!("{}Z", trimmed.replacen(' ', "T", 1));
    let time = Ts::parse_iso8601_utc(&iso)?;
    if trimmed.contains('.') {
        Some(time)
    } else {
        time.ticks()
            .map(|ticks| Ts::from_ticks(ticks, Precision::Second))
    }
}

/// Each row of `table`, converted; none when the table is absent.
fn rows<T>(
    db: &Database<'_>,
    table: &str,
    problems: &mut Vec<String>,
    mut convert: impl FnMut(&Named<'_>, &mut Vec<String>) -> T,
) -> Vec<T> {
    let Some(columns) = column_names(db, table) else {
        return Vec::new();
    };
    let mut rows = match db.rows(table) {
        Ok(rows) => rows,
        Err(e) => {
            problems.push(format!("{table}: {e}"));
            return Vec::new();
        }
    };
    let mut converted = Vec::new();
    for row in rows.by_ref() {
        let named = Named {
            table,
            columns: &columns,
            rowid: Some(row.rowid),
            values: row.values.iter().map(Some).collect(),
        };
        converted.push(convert(&named, problems));
    }
    problems.extend(rows.problems().iter().map(|p| format!("{table}: {p}")));
    converted
}

fn column_names(db: &Database<'_>, table: &str) -> Option<Vec<String>> {
    db.table(table)
        .map(|t| t.column_names().into_iter().map(str::to_owned).collect())
}

fn session(row: &Named<'_>, problems: &mut Vec<String>) -> Session {
    let custom_properties = (1..=CUSTOM_PROPERTIES)
        .map(|n| format!("CustomProperty{n}"))
        .filter_map(|column| {
            let value = row.text(&column).filter(|v| !v.is_empty())?;
            Some((column, value))
        })
        .collect();
    Session {
        rowid: row.rowid.unwrap_or_default(),
        id: row.guid("SessionID", problems),
        name: row.text("Name"),
        session_type: row.text("SessionType"),
        host: row.text("Host"),
        custom_properties,
    }
}

fn connection(row: &Named<'_>, problems: &mut Vec<String>) -> Connection {
    Connection {
        rowid: row.rowid.unwrap_or_default(),
        session_id: row.guid("SessionID", problems),
        id: row.guid("ConnectionID", problems),
        process_type: row.text("ProcessType"),
        participant_name: row.text("ParticipantName"),
        network_address: row.text("NetworkAddress"),
        client_type: row.text("ClientType"),
        client_version: row.text("ClientVersion"),
        connected: row.time("ConnectedTime", problems),
        disconnected: row.time("DisconnectedTime", problems),
    }
}

fn event(row: &Named<'_>, source: EventSource, problems: &mut Vec<String>) -> Event {
    let (event_type, event_name) = match row.value("EventType") {
        Some(Value::Integer(number)) => (
            Some(*number),
            EVENT_NAMES
                .iter()
                .find(|(known, _)| known == number)
                .map(|(_, name)| (*name).to_owned()),
        ),
        Some(Value::Text(text)) => (None, Some(text.clone())),
        _ => (None, None),
    };
    Event {
        source,
        rowid: row.rowid,
        session_id: row.guid("SessionID", problems),
        connection_id: row.guid("ConnectionID", problems),
        id: row.guid("EventID", problems),
        time: row.time("Time", problems),
        event_type,
        event_name,
        host: row.text("Host"),
        data: row.text("Data"),
    }
}

/// Events recovered from deleted records of the event tables.
fn deleted_events(db: &Database<'_>, problems: &mut Vec<String>) -> Vec<Event> {
    let recovered = db.recover();
    problems.extend(recovered.problems.iter().map(|p| format!("recovery: {p}")));
    let tables = [
        (SESSION_EVENTS, EventSource::Session),
        (CONNECTION_EVENTS, EventSource::Connection),
    ];
    let mut events = Vec::new();
    for (table, source) in tables {
        let Some(columns) = column_names(db, table) else {
            continue;
        };
        let records = recovered
            .records
            .iter()
            .chain(&recovered.older_versions)
            .filter(|record| record.table.as_deref() == Some(table));
        for record in records {
            events.push(event(&named(table, &columns, record), source, problems));
        }
    }
    events
}

fn named<'r>(table: &'r str, columns: &'r [String], record: &'r RecoveredRecord) -> Named<'r> {
    Named {
        table,
        columns,
        rowid: record.rowid,
        values: record.values.iter().map(Option::as_ref).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        let time = parse_time("2024-02-19 21:14:03.1234567").unwrap();
        assert_eq!(
            time.to_iso8601().as_deref(),
            Some("2024-02-19T21:14:03.1234567Z")
        );
        let seconds = parse_time("2024-02-19T21:14:03Z").unwrap();
        assert_eq!(seconds.precision(), Precision::Second);
        assert_eq!(parse_time("yesterday"), None);
    }

    #[test]
    fn not_a_database() {
        assert!(sessions(b"not sqlite", &[]).is_err());
    }
}
