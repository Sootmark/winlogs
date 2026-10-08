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
        let _ = winlogs::transcript::read(data);
        let _ = winlogs::teamviewer::log(data);
        let _ = winlogs::teamviewer::connections(data, true);
        let _ = winlogs::teamviewer::connections(data, false);
        let _ = winlogs::setupapi::read(data);
        let _ = winlogs::sccm::read(data);
        let _ = winlogs::anydesk::trace(data);
        let _ = winlogs::anydesk::connections(data);
        let _ = winlogs::detect("x.log", data);
    }

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let _ = winlogs::w3c::read(&data);
        let _ = winlogs::sccm::read(&data);
        let _ = winlogs::transcript::read(&data);
    }
}
