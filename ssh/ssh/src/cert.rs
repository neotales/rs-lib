//! OpenSSH certificate parsing and verification.
//!
//! The certificate format and its checks live in `neotales-x509`. This module
//! re-exports that API for SSH callers.

pub use neotales_x509::ssh_cert::{
    CERTIFICATE_TYPE_HOST, CERTIFICATE_TYPE_USER, CRITICAL_OPTION_FORCE_COMMAND,
    CRITICAL_OPTION_SOURCE_ADDRESS, Certificate, CertificateError, CertificateOption,
    CertificateType, ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH, SSH_ECDSA_SHA2_NISTP256,
    SSH_ECDSA_SHA2_NISTP256_CERT_V01, SSH_ECDSA_SHA2_NISTP384, SSH_ECDSA_SHA2_NISTP384_CERT_V01,
    SSH_ECDSA_SHA2_NISTP521, SSH_ECDSA_SHA2_NISTP521_CERT_V01, SSH_ED25519, SSH_ED25519_CERT_V01,
    SSH_RSA, SSH_RSA_CERT_V01, SUPPORTED_CERTIFICATE_ALGORITHMS, VerifiedCertificate, WireError,
    parse_certificate, verify_certificate,
};
