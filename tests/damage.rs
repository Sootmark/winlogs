//! Any input gives entries, problems or nothing, never a panic.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_text(text in "[ -~\t\n|\\[\\]<>*:#.-]{0,600}") {
        let data = text.as_bytes();
        let _ = winlogs::pca::launches(data);
        let _ = winlogs::pca::general(data);
        let _ = winlogs::w3c::read(data);
        let _ = winlogs::wer::report(data);
        let _ = winlogs::transcript::read(data);
        let _ = winlogs::teamviewer::log(data);
        let _ = winlogs::teamviewer::connections(data, true);
        let _ = winlogs::teamviewer::connections(data, false);
        let _ = winlogs::setupapi::read(data);
        let _ = winlogs::sccm::read(data);
        let _ = winlogs::anydesk::trace(data);
        let _ = winlogs::anydesk::connections(data);
        let _ = winlogs::screenconnect::config(data);
        let _ = winlogs::screenconnect::launch_parameters(&text);
        let _ = winlogs::detect("x.log", data);
        let _ = winlogs::detect("user.config", data);
    }

    #[test]
    fn arbitrary_markup(text in r#"(<[a-z/!?]{0,3}|[a-z ='"&;#%+?]|setting|value|name="|CDATA\[|]]>|-->|/>|>){0,120}"#) {
        let config = winlogs::screenconnect::config(text.as_bytes());
        prop_assert!(config.settings.len() <= text.len());
    }

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let _ = winlogs::w3c::read(&data);
        let _ = winlogs::sccm::read(&data);
        let _ = winlogs::transcript::read(&data);
        let _ = winlogs::screenconnect::config(&data);
        let _ = winlogs::screenconnect::sessions(&data, &[]);
    }

    #[test]
    fn session_databases_damaged(
        changes in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..64),
        cut in any::<usize>(),
    ) {
        let mut data = session_database();
        let len = data.len();
        for (at, byte) in changes {
            data[at % len] = byte;
        }
        let _ = winlogs::screenconnect::sessions(&data[..cut % (len + 1)], &[]);
        let _ = winlogs::screenconnect::sessions(&data, &[]);
    }
}

fn session_database() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/written/screenconnect/Session.db",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
