//! Argon2 read and save budgets and typed limit diagnostics.

use neotales_keepass::{
    KdbxCredentials, KdbxError, KdbxFailureKind, KdbxFile, KdbxKdf, KdbxLimitDetail,
    KdbxLimitParameter, KdbxReadLimits, KdbxWriteOptions, KeePassDatabase,
};

fn assert_limit(error: &KdbxError, expected: KdbxLimitDetail) {
    assert_eq!(error.kind, KdbxFailureKind::ResourceLimit);
    assert_eq!(error.limit_detail(), Some(&expected));
}

#[test]
fn default_argon2_limits() {
    let limits = KdbxReadLimits::default();
    assert_eq!(limits.max_argon2_memory_kib, 1_048_576);
    assert_eq!(limits.max_argon2_time, 4096);
    assert_eq!(limits.max_argon2_lanes, 64);
    assert_eq!(limits.max_argon2_work_kib_passes, 16_777_216);
}

#[test]
fn argon2_vaults_above_ten_passes_open_with_defaults() {
    let limits = KdbxReadLimits::default();
    for kdf in [KdbxKdf::Argon2d, KdbxKdf::Argon2id] {
        let options = KdbxWriteOptions {
            kdf,
            argon2_memory_kib: 32,
            argon2_time: 11,
            argon2_lanes: 2,
            ..KdbxWriteOptions::default()
        };
        let database = KeePassDatabase::default();
        let mut bytes = Vec::new();
        KdbxFile::save(
            &database,
            &mut bytes,
            &mut KdbxCredentials::password("test-password").unwrap(),
            options,
            &limits,
        )
        .unwrap();
        KdbxFile::load_password(bytes.as_slice(), "test-password", &limits).unwrap();

        // Lanes do not multiply total memory. Equality must allow read and save.
        let exact = KdbxReadLimits {
            max_argon2_work_kib_passes: 32 * 11,
            ..limits
        };
        KdbxFile::load_password(bytes.as_slice(), "test-password", &exact).unwrap();
        KdbxFile::save(
            &database,
            &mut Vec::new(),
            &mut KdbxCredentials::password("test-password").unwrap(),
            options,
            &exact,
        )
        .unwrap();

        for (policy, parameter, actual, maximum) in [
            (
                KdbxReadLimits {
                    max_argon2_memory_kib: 31,
                    max_argon2_time: 10,
                    max_argon2_lanes: 1,
                    max_argon2_work_kib_passes: 1,
                    ..limits
                },
                KdbxLimitParameter::Argon2Memory,
                32,
                31,
            ),
            (
                KdbxReadLimits {
                    max_argon2_time: 10,
                    max_argon2_lanes: 1,
                    max_argon2_work_kib_passes: 1,
                    ..limits
                },
                KdbxLimitParameter::Argon2Time,
                11,
                10,
            ),
            (
                KdbxReadLimits {
                    max_argon2_lanes: 1,
                    max_argon2_work_kib_passes: 1,
                    ..limits
                },
                KdbxLimitParameter::Argon2Lanes,
                2,
                1,
            ),
            (
                KdbxReadLimits {
                    max_argon2_work_kib_passes: 351,
                    ..limits
                },
                KdbxLimitParameter::Argon2Work,
                352,
                351,
            ),
        ] {
            let expected = KdbxLimitDetail {
                parameter,
                actual,
                maximum,
            };
            let read_error =
                KdbxFile::load_password(bytes.as_slice(), "test-password", &policy).unwrap_err();
            assert_limit(&read_error, expected);
            let mut output = Vec::new();
            let save_error = KdbxFile::save(
                &database,
                &mut output,
                &mut KdbxCredentials::password("test-password").unwrap(),
                options,
                &policy,
            )
            .unwrap_err();
            assert_limit(&save_error, expected);
            assert!(output.is_empty());
        }
    }
}

#[test]
fn zero_work_limit_is_invalid() {
    let limits = KdbxReadLimits {
        max_argon2_work_kib_passes: 0,
        ..KdbxReadLimits::default()
    };
    let error = limits.validate().unwrap_err();
    assert_eq!(error.kind, KdbxFailureKind::InvalidArgument);
    assert_eq!(error.limit_detail(), None);
}
