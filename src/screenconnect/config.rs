//! ScreenConnect's client configuration: .NET settings files,
//!
//! ```xml
//! <configuration>
//!   <ScreenConnect.ApplicationSettings>
//!     <setting name="…" serializeAs="String"><value>?h=relay.example.com&amp;p=443&amp;k=…</value></setting>
//!   </ScreenConnect.ApplicationSettings>
//! </configuration>
//! ```
//!
//! read as their sections' settings, without an XML library: elements are
//! followed by name, the declaration, comments, processing instructions and
//! the document type skipped, the five predefined entities and character
//! references decoded, CDATA sections read as text.

use crate::decode;

/// Elements nested deeper than this aren't followed (settings files nest
/// four levels).
const MAX_DEPTH: usize = 64;

/// A setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// Its section: the element around it (`ScreenConnect.ApplicationSettings`).
    pub section: String,
    /// Its name.
    pub name: String,
    /// Its value, decoded; a value serialised as XML is kept as written.
    pub value: String,
}

/// A client's launch parameters, the query string it connects with
/// (ConnectWise's integration guide names them).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchParameters {
    /// `e`: the session type (`Support`, `Meet`, `Access`).
    pub session_type: Option<String>,
    /// `y`: the process type (`Guest`, `Host`).
    pub process_type: Option<String>,
    /// `h`: the relay's host.
    pub relay_host: Option<String>,
    /// `p`: the relay's port, as written.
    pub relay_port: Option<String>,
    /// `s`: the session's id (a GUID).
    pub session_id: Option<String>,
    /// `k`: the server's public key, as written (encoded).
    pub key: Option<String>,
    /// `c`: the custom property values, in order.
    pub custom_properties: Vec<String>,
    /// Every parameter, decoded, in order.
    pub all: Vec<(String, String)>,
}

/// A configuration file read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// Every setting, in file order.
    pub settings: Vec<Setting>,
    /// The launch parameters of the first setting holding them.
    pub launch: Option<LaunchParameters>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The settings of a `system.config` or `user.config`.
#[must_use]
pub fn config(data: &[u8]) -> Config {
    let text = decode(data);
    let mut config = Config::default();
    Scanner {
        text: &text,
        at: 0,
        open: Vec::new(),
        config: &mut config,
    }
    .run();
    config.launch = config
        .settings
        .iter()
        .find_map(|setting| launch_parameters(&setting.value));
    config
}

/// The launch parameters in `text`: the query string after its first `?`
/// (to the end, a quote or a blank), `&`-separated `name=value` pairs,
/// form-decoded (`+` a space, `%XX` a UTF-8 byte); `None` without a `?`
/// followed by a relay host (`h`) or session id (`s`). Reads the client
/// service's `ImagePath` too.
#[must_use]
pub fn launch_parameters(text: &str) -> Option<LaunchParameters> {
    let query = text.split_once('?')?.1;
    let query = query
        .split(|c: char| c == '"' || c.is_whitespace())
        .next()
        .unwrap_or_default();
    let mut parameters = LaunchParameters::default();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (name, value) = (form_decode(name), form_decode(value));
        let field = match name.as_str() {
            "e" => Some(&mut parameters.session_type),
            "y" => Some(&mut parameters.process_type),
            "h" => Some(&mut parameters.relay_host),
            "p" => Some(&mut parameters.relay_port),
            "s" => Some(&mut parameters.session_id),
            "k" => Some(&mut parameters.key),
            "c" => {
                parameters.custom_properties.push(value.clone());
                None
            }
            _ => None,
        };
        if let Some(field) = field {
            field.get_or_insert_with(|| value.clone());
        }
        parameters.all.push((name, value));
    }
    (parameters.relay_host.is_some() || parameters.session_id.is_some()).then_some(parameters)
}

/// `+` as a space and `%XX` as a byte, the bytes read as UTF-8 (lossy); a
/// `%` not followed by two hexadecimal digits kept.
fn form_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let escaped = (bytes[at] == b'%')
            .then(|| text.get(at + 1..at + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match (bytes[at], escaped) {
            (_, Some(byte)) => {
                decoded.push(byte);
                at += 3;
            }
            (b'+', None) => {
                decoded.push(b' ');
                at += 1;
            }
            (byte, None) => {
                decoded.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Walks the markup, element by element.
struct Scanner<'t, 'c> {
    text: &'t str,
    at: usize,
    /// The names of the elements open.
    open: Vec<&'t str>,
    config: &'c mut Config,
}

impl Scanner<'_, '_> {
    fn run(&mut self) {
        while let Some(offset) = self.text[self.at..].find('<') {
            self.at += offset;
            let rest = &self.text[self.at..];
            let skipped = [
                ("<?", "?>"),
                ("<!--", "-->"),
                ("<![CDATA[", "]]>"),
                ("<!", ">"),
            ]
            .iter()
            .find(|(start, _)| rest.starts_with(start));
            if let Some((_, end)) = skipped {
                self.skip_past(end);
            } else if let Some(name) = rest.strip_prefix("</") {
                let name = name.split('>').next().unwrap_or_default().trim();
                self.close(name);
                self.skip_past(">");
            } else {
                self.element();
            }
        }
        if let Some(open) = self.open.last() {
            self.config
                .problems
                .push(format!("<{open}> isn't closed at the end"));
        }
    }

    fn skip_past(&mut self, end: &str) {
        self.at = match self.text[self.at..].find(end) {
            Some(offset) => self.at + offset + end.len(),
            None => self.text.len(),
        };
    }

    /// The start tag at `at`, and for a setting its value.
    fn element(&mut self) {
        let start = self.at;
        let Some(length) = self.text[start..].find('>') else {
            self.config
                .problems
                .push(format!("offset {start}: a tag isn't closed"));
            self.at = self.text.len();
            return;
        };
        let tag = &self.text[start + 1..start + length];
        self.at = start + length + 1;
        let self_closing = tag.ends_with('/');
        let tag = tag.trim_end_matches('/');
        let name = tag.split_whitespace().next().unwrap_or_default();
        if name == "setting" {
            let section = self.open.last().copied().unwrap_or_default().to_owned();
            let setting_name = attribute(tag, "name").unwrap_or_default();
            let value = if self_closing {
                String::new()
            } else {
                self.value()
            };
            self.config.settings.push(Setting {
                section,
                name: setting_name,
                value,
            });
        } else if !self_closing {
            if self.open.len() < MAX_DEPTH {
                self.open.push(name);
            } else {
                self.config
                    .problems
                    .push(format!("offset {start}: nested deeper than {MAX_DEPTH}"));
            }
        }
    }

    /// The value of the setting whose start tag ends at `at`, the scanner
    /// moved past the setting's end.
    fn value(&mut self) -> String {
        let body_start = self.at;
        let Some(length) = self.text[body_start..].find("</setting>") else {
            self.config
                .problems
                .push(format!("offset {body_start}: a setting isn't closed"));
            self.at = self.text.len();
            return String::new();
        };
        let body = &self.text[body_start..body_start + length];
        self.at = body_start + length + "</setting>".len();
        if body.contains("<value/>") || body.contains("<value />") {
            return String::new();
        }
        let inner = body
            .split_once("<value>")
            .and_then(|(_, after)| after.rsplit_once("</value>"))
            .map(|(inner, _)| inner);
        match inner {
            Some(inner) if inner.trim_start().starts_with("<![CDATA[") => {
                let cdata = inner.trim().trim_start_matches("<![CDATA[");
                cdata.strip_suffix("]]>").unwrap_or(cdata).to_owned()
            }
            Some(inner) if inner.contains('<') => inner.trim().to_owned(),
            Some(inner) => unescape(inner),
            None => {
                self.config
                    .problems
                    .push(format!("offset {body_start}: a setting without a value"));
                String::new()
            }
        }
    }

    /// Closes the element `name` and those opened after it; a stray end tag
    /// is reported and skipped.
    fn close(&mut self, name: &str) {
        match self.open.iter().rposition(|open| *open == name) {
            Some(at) => {
                for unclosed in &self.open[at + 1..] {
                    self.config
                        .problems
                        .push(format!("<{unclosed}> closed by </{name}>"));
                }
                self.open.truncate(at);
            }
            None => self
                .config
                .problems
                .push(format!("offset {}: a stray </{name}>", self.at)),
        }
    }
}

/// The value of attribute `name` in a start tag's text.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let mut rest = tag;
    while let Some(at) = rest.find(name) {
        let before_ok = rest[..at].ends_with(char::is_whitespace);
        let after = rest[at + name.len()..].trim_start();
        if let (true, Some(after)) = (before_ok, after.strip_prefix('=')) {
            let after = after.trim_start();
            let quote = after.chars().next().filter(|c| *c == '"' || *c == '\'')?;
            let value = after[1..].split(quote).next()?;
            return Some(unescape(value));
        }
        rest = &rest[at + name.len()..];
    }
    None
}

/// The predefined entities and character references decoded; an unknown
/// one kept as written.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let decoded = rest.find(';').and_then(|end| {
            let character = match &rest[1..end] {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                reference => reference
                    .strip_prefix("#x")
                    .or_else(|| reference.strip_prefix("#X"))
                    .map(|hex| u32::from_str_radix(hex, 16))
                    .or_else(|| reference.strip_prefix('#').map(str::parse::<u32>))
                    .and_then(Result::ok)
                    .and_then(char::from_u32),
            };
            character.map(|c| (c, end))
        });
        if let Some((character, end)) = decoded {
            out.push(character);
            rest = &rest[end + 1..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <!-- a comment <setting name="no"> -->
  <ScreenConnect.ApplicationSettings>
    <setting name="ClientLaunchParametersConstraint" serializeAs="String">
      <value>?h=relay.example.com&amp;p=8041&amp;k=BgIAAACkAABSU0Ex%2bAB&amp;c=Acme+Corp&amp;c=&amp;c=Desk%20one</value>
    </setting>
    <setting name="Empty" serializeAs="String"><value /></setting>
  </ScreenConnect.ApplicationSettings>
</configuration>"#;

    #[test]
    fn settings_and_launch_parameters() {
        let config = config(SYSTEM.as_bytes());
        assert_eq!(config.problems, Vec::<String>::new());
        assert_eq!(config.settings.len(), 2);
        assert_eq!(
            config.settings[0].section,
            "ScreenConnect.ApplicationSettings"
        );
        assert_eq!(config.settings[0].name, "ClientLaunchParametersConstraint");
        assert_eq!(config.settings[1].value, "");
        let launch = config.launch.unwrap();
        assert_eq!(launch.relay_host.as_deref(), Some("relay.example.com"));
        assert_eq!(launch.relay_port.as_deref(), Some("8041"));
        assert_eq!(launch.key.as_deref(), Some("BgIAAACkAABSU0Ex+AB"));
        assert_eq!(launch.custom_properties, ["Acme Corp", "", "Desk one"]);
        assert_eq!(launch.session_id, None);
    }

    #[test]
    fn an_image_path() {
        let path = r#""C:\Program Files (x86)\ScreenConnect Client (e6f5ce1d563c8e3f)\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=instance-x-relay.screenconnect.com&p=443&s=99087e24-0000-4000-8000-000000000001&k=AB%3d%3d&r=&i=Untitled%20Session" "1""#;
        let launch = launch_parameters(path).unwrap();
        assert_eq!(launch.session_type.as_deref(), Some("Access"));
        assert_eq!(launch.process_type.as_deref(), Some("Guest"));
        assert_eq!(
            launch.session_id.as_deref(),
            Some("99087e24-0000-4000-8000-000000000001")
        );
        assert_eq!(launch.key.as_deref(), Some("AB=="));
        assert_eq!(
            launch.all.last().unwrap(),
            &("i".to_owned(), "Untitled Session".to_owned())
        );
        assert_eq!(launch_parameters("no query"), None);
        assert_eq!(launch_parameters("?x=1"), None);
    }

    #[test]
    fn markup_quirks() {
        assert_eq!(unescape("a&lt;b&#65;&#x42;&bogus;&"), "a<bAB&bogus;&");
        assert_eq!(form_decode("%e2%82%ac+%zz%4"), "€ %zz%4");
        assert_eq!(
            attribute(r#"setting xname="x" name='y'"#, "name").as_deref(),
            Some("y")
        );
        let cdata =
            r#"<c><s><setting name="a"><value><![CDATA[<x>&amp;]]></value></setting></s></c>"#;
        assert_eq!(config(cdata.as_bytes()).settings[0].value, "<x>&amp;");
        let damaged = config(b"<c><s><setting name=\"a\"><value>1</value></setting></x><open");
        assert_eq!(damaged.settings[0].value, "1");
        assert_eq!(
            damaged.problems,
            [
                "offset 50: a stray </x>",
                "offset 54: a tag isn't closed",
                "<s> isn't closed at the end"
            ]
        );
    }
}
