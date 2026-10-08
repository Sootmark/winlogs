//! Windows Error Reporting reports written as Windows writes them
//! (`tests/fixtures/written/wer/`, see the NOTICE): every value compared
//! with what Python's own codecs read from them (`tests/oracle/wer.tsv`,
//! written by `tests/oracle/gen_wer.py`).

use winlogs::{detect, wer, Kind};

#[test]
fn every_value_as_python_reads_it() {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/written/wer");
    let mut reports: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    reports.sort();
    let mut got = Vec::new();
    for name in &reports {
        let path = format!("{folder}/{name}/Report.wer");
        let data = std::fs::read(&path).unwrap();
        assert_eq!(detect(&path, &data), Some(Kind::WerReport));
        assert_eq!(detect("renamed.txt", &data), Some(Kind::WerReport));
        let parsed = wer::report(&data);
        assert!(parsed.problems.is_empty(), "{:?}", parsed.problems);
        let r = &parsed.entries[0];
        let mut out = |what: &str, value: Option<String>| {
            if let Some(value) = value {
                got.push(format!("{name}\t{what}\t{value}"));
            }
        };
        out("event_type", r.event_type.clone());
        out("time", r.time.and_then(|t| t.to_iso8601()));
        out("upload_time", r.upload_time.and_then(|t| t.to_iso8601()));
        out("app_path", r.app_path.clone());
        for (n, v) in &r.signature {
            out("signature", Some(format!("{n}={v}")));
        }
        for (n, v) in &r.dynamic_signature {
            out("dynamic_signature", Some(format!("{n}={v}")));
        }
        for module in &r.loaded_modules {
            out("module", Some(module.clone()));
        }
    }
    let expected: Vec<&str> = include_str!("oracle/wer.tsv").lines().collect();
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert_eq!(got.len(), expected.len());
}

#[test]
fn named_values() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/written/wer/lsass/Report.wer"
    ))
    .unwrap();
    let report = &wer::report(&data).entries[0];
    assert_eq!(report.signature("Fault Module Name"), Some("dbghelp.dll"));
    assert_eq!(report.get("consentkey"), Some("APPCRASH"));
    assert_eq!(
        report.friendly_event_name.as_deref(),
        Some("Stopped working")
    );
    assert!(wer::report(b"").entries.is_empty());
}
