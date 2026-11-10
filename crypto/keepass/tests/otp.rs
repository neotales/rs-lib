// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use neotales_keepass::{
    Entry, Hotp, HotpParameters, KeePassXcOtp, OtpAlgorithm, OtpDigits, OtpSecret, OtpUri,
};

#[test]
fn hotp_rfc4226_vectors() {
    let secret = b"12345678901234567890";
    let parameters = HotpParameters {
        secret,
        algorithm: OtpAlgorithm::Sha1,
        digits: OtpDigits::Six,
        counter: 0,
    };
    assert_eq!(Hotp::generate(&parameters), "755224");
    assert_eq!(
        Hotp::generate(&HotpParameters {
            counter: 1,
            ..parameters
        }),
        "287082"
    );
}

#[test]
fn keepassxc_modern_otp_field_round_trips() {
    let uri = OtpUri::parse("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30").unwrap();
    let mut entry = Entry::new("alice");
    KeePassXcOtp::write(&mut entry, &uri);
    assert!(KeePassXcOtp::is_present(&entry));
    let loaded = KeePassXcOtp::read(&entry).unwrap();
    assert_eq!(loaded.secret, "JBSWY3DPEHPK3PXP");
    assert!(!format!("{loaded:?}").contains("JBSWY3DPEHPK3PXP"));
    assert!(format!("{loaded}").contains("JBSWY3DPEHPK3PXP"));
    assert!(KeePassXcOtp::remove(&mut entry));
}

#[test]
fn base32_decodes_strict_secrets() {
    let secret = OtpSecret::from_base32("JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(secret.expose(), b"Hello!\xde\xad\xbe\xef");
    assert!(OtpSecret::from_base32("JBSWY3DPEHPK3PX!").is_err());
    assert!(OtpUri::parse("otpauth://totp/a?secret=not-base32!&period=30").is_err());
}
