//! plaso's test logs (Apache-2.0, `tests/fixtures/plaso/`, gzip-compressed):
//! every entry plaso reads, read the same (`tests/oracle/plaso.tsv.gz`,
//! written from plaso's own output, see `tests/oracle/README`), and the
//! entries this crate reads beyond plaso's, counted.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use common::time::Ts;
use winlogs::Kind;

fn gunzip(compressed: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed)
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// The wall clock to the millisecond, as plaso shows it.
fn wall(time: Option<Ts>) -> String {
    time.and_then(|t| t.to_iso8601())
        .map(|text| text[..23].to_owned())
        .unwrap_or_default()
}

/// Every entry of the fixtures, as the oracle writes them.
fn lines() -> Vec<String> {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/plaso");
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".gz").map(str::to_owned))
        .collect();
    names.sort();
    names
        .iter()
        .flat_map(|name| {
            let data = gunzip(&std::fs::read(format!("{folder}/{name}.gz")).unwrap());
            file_lines(name, &data)
        })
        .map(|fields| fields.join("\t"))
        .collect()
}

/// A file's entries as the oracle's fields, the kind and file first.
fn file_lines(name: &str, data: &[u8]) -> Vec<Vec<String>> {
    let kind = winlogs::detect(name, data).unwrap_or_else(|| panic!("{name}: not detected"));
    let rows = match kind {
        Kind::PcaLaunches | Kind::PcaGeneral => pca(kind, data),
        Kind::W3c => w3c(data),
        Kind::Transcript => transcript(data),
        Kind::TeamViewerLog | Kind::TeamViewerIncoming | Kind::TeamViewerOutgoing => {
            teamviewer(kind, data)
        }
        Kind::SetupApi => setupapi(data),
        Kind::Sccm => sccm(data),
    };
    rows.into_iter()
        .map(|(tag, mut fields)| {
            fields.insert(0, name.to_owned());
            fields.insert(0, tag.to_owned());
            fields
        })
        .collect()
}

type Rows = Vec<(&'static str, Vec<String>)>;

fn pca(kind: Kind, data: &[u8]) -> Rows {
    if kind == Kind::PcaLaunches {
        return winlogs::pca::launches(data)
            .entries
            .into_iter()
            .map(|e| ("pca_dic", vec![wall(Some(e.last_run)), e.program]))
            .collect();
    }
    winlogs::pca::general(data)
        .entries
        .into_iter()
        .map(|e| {
            let fields = vec![
                wall(Some(e.time)),
                e.program,
                e.run_status,
                e.program_id,
                e.exit_code,
            ];
            ("pca_db0", fields)
        })
        .collect()
}

fn w3c(data: &[u8]) -> Rows {
    winlogs::w3c::read(data)
        .entries
        .iter()
        .map(|e| {
            let get = |field: &str| e.get(field).unwrap_or_default().to_owned();
            let fields = vec![
                wall(e.time),
                get("cs-method"),
                get("cs-uri-stem"),
                get("c-ip"),
                get("sc-status"),
            ];
            ("iis", fields)
        })
        .collect()
}

fn transcript(data: &[u8]) -> Rows {
    let transcript = winlogs::transcript::read(data);
    let get = |field: &str| transcript.get(field).unwrap_or_default().to_owned();
    transcript
        .blocks
        .iter()
        .map(|block| {
            let fields = vec![
                wall(block.time),
                get("Username"),
                get("ProcessId"),
                block.lines.join("; "),
            ];
            ("ps", fields)
        })
        .collect()
}

fn teamviewer(kind: Kind, data: &[u8]) -> Rows {
    if kind == Kind::TeamViewerLog {
        return winlogs::teamviewer::log(data)
            .entries
            .into_iter()
            .map(|e| {
                let fields = vec![
                    wall(Some(e.time)),
                    e.process.to_string(),
                    e.message.replace('\n', "\\n"),
                ];
                ("tvlog", fields)
            })
            .collect();
    }
    winlogs::teamviewer::connections(data, kind == Kind::TeamViewerIncoming)
        .entries
        .into_iter()
        .map(|c| {
            (
                "tvconn",
                vec![wall(c.start), c.remote_id, c.account, c.kind, c.id],
            )
        })
        .collect()
}

fn setupapi(data: &[u8]) -> Rows {
    winlogs::setupapi::read(data)
        .entries
        .into_iter()
        .flat_map(|section| {
            let status = section.exit_status.clone().unwrap_or_default();
            [
                (
                    "setupapi_start",
                    vec![wall(section.start), section.title.clone(), status.clone()],
                ),
                (
                    "setupapi_end",
                    vec![wall(section.end), section.title, status],
                ),
            ]
        })
        .collect()
}

fn sccm(data: &[u8]) -> Rows {
    winlogs::sccm::read(data)
        .entries
        .into_iter()
        .map(|e| ("sccm", vec![e.component, e.text.replace('\n', "\\n")]))
        .collect()
}

#[test]
fn every_plaso_entry_is_read_the_same() {
    let read = lines();
    let ours: BTreeSet<&str> = read.iter().map(String::as_str).collect();
    let compressed = include_bytes!("oracle/plaso.tsv.gz");
    let oracle = String::from_utf8(gunzip(compressed)).unwrap();
    let missing: Vec<&str> = oracle.lines().filter(|l| !ours.contains(l)).collect();
    assert_eq!(missing, Vec::<&str>::new());
    assert_eq!(oracle.lines().count(), 1356);
}

#[test]
fn entries_beyond_plaso_are_counted() {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for line in lines() {
        *counts
            .entry(line.split('\t').next().unwrap().to_owned())
            .or_default() += 1;
    }
    let counts: Vec<(&str, usize)> = counts.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    // Beyond plaso: the IIS line plaso's grammar rejects and the firewall
    // log's 15 entries (plaso's own test expects 15, its command line gives
    // none); 23 setupapi sections plaso skips; a transcript's last block,
    // which no separator closes; TeamViewer's repeated lines (psort keeps
    // one of each).
    assert_eq!(
        counts,
        [
            ("iis", 63),
            ("pca_db0", 3),
            ("pca_dic", 4),
            ("ps", 4),
            ("sccm", 10),
            ("setupapi_end", 210),
            ("setupapi_start", 210),
            ("tvconn", 2),
            ("tvlog", 1013)
        ]
    );
}
