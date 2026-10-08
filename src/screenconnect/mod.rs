//! ConnectWise ScreenConnect (formerly ConnectWise Control), remote access
//! in and out:
//!
//! - [`config`]: the client's `system.config` (`Program Files
//!   (x86)\ScreenConnect Client (<thumbprint>)`) and `user.config` (a
//!   user's `AppData\Local\ScreenConnect Client (<thumbprint>)`): .NET
//!   settings files, every setting read; the launch parameters
//!   (`?e=Access&y=Guest&h=<relay host>&p=<port>&s=<session id>&k=…`) in
//!   them, and in the service's `ImagePath` ([`launch_parameters`]), name
//!   the relay the client connects to and its session.
//! - [`sessions`]: the server's `App_Data\Session.db` (SQLite): sessions,
//!   connections (participant, host or guest, address, connected and
//!   disconnected times) and session events (commands queued and run,
//!   transfers, messages), deleted events recovered.
//!
//! The server's and the toolbox's `*.log` files have no documented format
//! and aren't read; the Application event log entries ScreenConnect writes
//! are read with the event logs.

mod config;
mod sessions;

pub use config::{config, launch_parameters, Config, LaunchParameters, Setting};
pub use sessions::{sessions, Connection, Event, EventSource, Session, SessionDatabase};
