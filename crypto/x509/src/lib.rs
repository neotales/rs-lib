#![allow(
    clippy::doc_markdown,
    reason = "algorithm names in this catalog are proper nouns, not Rust items"
)]

//! X.509 identifiers, certificate generation, and SSH wire conversion.
//!
//! This crate keeps the shared X.509 object-identifier catalog, converts
//! complete DER certificates to and from the RFC 6187 SSH public-key blob,
//! and converts between X.509 SubjectPublicKeyInfo and OpenSSH v01
//! certificates. An SSH private key plus its matching public line becomes a
//! self-signed X.509 certificate, a PKCS#8 private key, and a
//! SubjectPublicKeyInfo public key. An OpenSSH v01 certificate still does not
//! contain a private key.

pub mod openssh_cert;
pub mod pem;
pub mod ssh;
pub mod ssh_cert;
pub mod ssh_keypair;

pub mod openssh_bcrypt;
mod ssh_wire;

pub use openssh_cert::OpenSshCertError;
pub use ssh::SshX509Error;
pub use ssh_keypair::{SshKeyError, SshKeyToX509, X509KeyPair, ssh_keypair_to_x509};

/// RFC 8410 Ed25519 object identifier.
pub const ED25519_OID: &str = "1.3.101.112";

/// DER `AlgorithmIdentifier` for Ed25519, with no parameters.
pub const ED25519_ALGORITHM_IDENTIFIER: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// Basic constraints extension.
pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";

/// Subject alternative name extension.
pub const SUBJECT_ALT_NAME: &str = "2.5.29.17";

/// Extended key usage extension.
pub const EXTENDED_KEY_USAGE: &str = "2.5.29.37";

/// Authority information access extension.
pub const AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";

/// Extended key usage and related object identifiers from the established object identifier set.
pub mod oids {
    /// Windows Update (`1.3.6.1.4.1.311.76.6.1`).
    pub const WINDOWS_UPDATE: &str = "1.3.6.1.4.1.311.76.6.1";
    /// Windows third-party application component.
    pub const WINDOWS_THIRD_PARTY_APPLICATION_COMPONENT: &str = "1.3.6.1.4.1.311.10.3.25";
    /// Windows system component verification.
    pub const WINDOWS_SYSTEM_COMPONENT_VERIFICATION: &str = "1.3.6.1.4.1.311.10.3.6";
    /// Windows TCB component.
    pub const WINDOWS_TCB_COMPONENT: &str = "1.3.6.1.4.1.311.10.3.23";
    /// Windows software extension verification.
    pub const WINDOWS_SOFTWARE_EXTENSION_VERIFICATION: &str = "1.3.6.1.4.1.311.10.3.26";
    /// Windows Store.
    pub const WINDOWS_STORE: &str = "1.3.6.1.4.1.311.76.3.1";
    /// Windows kits component.
    pub const WINDOWS_KITS_COMPONENT: &str = "1.3.6.1.4.1.311.10.3.20";
    /// Windows hardware driver attested verification.
    pub const WINDOWS_HARDWARE_DRIVER_ATTESTED_VERIFICATION: &str = "1.3.6.1.4.1.311.10.3.5.1";
    /// Windows hardware driver verification.
    pub const WINDOWS_HARDWARE_DRIVER_VERIFICATION: &str = "1.3.6.1.4.1.311.10.3.5";
    /// Windows hardware driver extended verification.
    pub const WINDOWS_HARDWARE_DRIVER_EXTENDED_VERIFICATION: &str = "1.3.6.1.4.1.311.10.3.39";
    /// Windows RT verification.
    pub const WINDOWS_RT_VERIFICATION: &str = "1.3.6.1.4.1.311.10.3.21";
    /// Key recovery.
    pub const KEY_RECOVERY: &str = "1.3.6.1.4.1.311.10.3.11";
    /// Key recovery agent.
    pub const KEY_RECOVERY_AGENT: &str = "1.3.6.1.4.1.311.21.6";
    /// Key pack licenses.
    pub const KEY_PACK_LICENSES: &str = "1.3.6.1.4.1.311.10.6.1";
    /// Early launch anti-malware driver.
    pub const EARLY_LAUNCH_ANTIMALWARE_DRIVER: &str = "1.3.6.1.4.1.311.61.4.1";
    /// Kernel-mode code signing.
    pub const KERNEL_MODE_CODE_SIGNING: &str = "1.3.6.1.4.1.311.61.1.1";
    /// Attestation identity key certificate.
    pub const ATTESTATION_IDENTITY_KEY_CERTIFICATE: &str = "2.23.133.8.3";
    /// Smart card logon.
    pub const SMART_CARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
    /// KDC authentication.
    pub const KDC_AUTHENTICATION: &str = "1.3.6.1.5.2.3.5";
    /// Embedded Windows system component verification.
    pub const EMBEDDED_WINDOWS_SYSTEM_COMPONENT_VERIFICATION: &str = "1.3.6.1.4.1.311.10.3.8";
    /// IPsec tunnel termination.
    pub const IP_SECURITY_TUNNEL_TERMINATION: &str = "1.3.6.1.5.5.7.3.6";
    /// IPsec IKE intermediate.
    pub const IP_SECURITY_IKE_INTERMEDIATE: &str = "1.3.6.1.5.5.8.2.2";
    /// IPsec user.
    pub const IP_SECURITY_USER: &str = "1.3.6.1.5.5.7.3.7";
    /// License server verification.
    pub const LICENSE_SERVER_VERIFICATION: &str = "1.3.6.1.4.1.311.10.6.2";
    /// Dynamic code generator.
    pub const DYNAMIC_CODE_GENERATOR: &str = "1.3.6.1.4.1.311.76.5.1";
    /// Time stamping.
    pub const TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
    /// File recovery.
    pub const FILE_RECOVERY: &str = "1.3.6.1.4.1.311.10.3.4.1";
    /// SPC relaxed PE marker check.
    pub const SPC_RELAXED_PE_MARKER_CHECK: &str = "1.3.6.1.4.1.311.2.6.1";
    /// Endorsement key certificate.
    pub const ENDORSEMENT_KEY_CERTIFICATE: &str = "2.23.133.8.1";
    /// SPC encrypted digest retry count.
    pub const SPC_ENCRYPTED_DIGEST_RETRY_COUNT: &str = "1.3.6.1.4.1.311.2.6.2";
    /// Encrypting file system.
    pub const ENCRYPTING_FILE_SYSTEM: &str = "1.3.6.1.4.1.311.10.3.4";
    /// Server authentication.
    pub const SERVER_AUTHENTICATION: &str = "1.3.6.1.5.5.7.3.1";
    /// HAL extension.
    pub const HAL_EXTENSION: &str = "1.3.6.1.4.1.311.61.5.1";
    /// Secure email.
    pub const SECURE_EMAIL: &str = "1.3.6.1.5.5.7.3.4";
    /// IPsec end system.
    pub const IP_SECURITY_END_SYSTEM: &str = "1.3.6.1.5.5.7.3.5";
    /// Root list signer.
    pub const ROOT_LIST_SIGNER: &str = "1.3.6.1.4.1.311.10.3.9";
    /// Disallowed list.
    pub const DISALLOWED_LIST: &str = "1.3.6.1.4.1.311.10.3.30";
    /// Revoked list signer.
    pub const REVOKED_LIST_SIGNER: &str = "1.3.6.1.4.1.311.10.3.19";
    /// Qualified subordination.
    pub const QUALIFIED_SUBORDINATION: &str = "1.3.6.1.4.1.311.10.3.10";
    /// Document signing.
    pub const DOCUMENT_SIGNING: &str = "1.3.6.1.4.1.311.10.3.12";
    /// Protected process verification.
    pub const PROTECTED_PROCESS_VERIFICATION: &str = "1.3.6.1.4.1.311.10.3.24";
    /// Document encryption.
    pub const DOCUMENT_ENCRYPTION: &str = "1.3.6.1.4.1.311.80.1";
    /// Protected process light verification.
    pub const PROTECTED_PROCESS_LIGHT_VERIFICATION: &str = "1.3.6.1.4.1.311.10.3.22";
    /// Directory service email replication.
    pub const DIRECTORY_SERVICE_EMAIL_REPLICATION: &str = "1.3.6.1.4.1.311.21.19";
    /// Private key archival.
    pub const PRIVATE_KEY_ARCHIVAL: &str = "1.3.6.1.4.1.311.21.5";
    /// Digital rights.
    pub const DIGITAL_RIGHTS: &str = "1.3.6.1.4.1.311.10.5.1";
    /// Preview build signing.
    pub const PREVIEW_BUILD_SIGNING: &str = "1.3.6.1.4.1.311.10.3.27";
    /// Certificate request agent.
    pub const CERTIFICATE_REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";
    /// Platform certificate.
    pub const PLATFORM_CERTIFICATE: &str = "2.23.133.8.2";
    /// CTL usage.
    pub const CTL_USAGE: &str = "1.3.6.1.4.1.311.20.1";
    /// OCSP signing.
    pub const OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
    /// Code signing.
    pub const CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
    /// Microsoft trust list signing.
    pub const MICROSOFT_TRUST_LIST_SIGNING: &str = "1.3.6.1.4.1.311.10.3.1";
    /// Microsoft time stamping.
    pub const MICROSOFT_TIME_STAMPING: &str = "1.3.6.1.4.1.311.10.3.2";
    /// Microsoft publisher.
    pub const MICROSOFT_PUBLISHER: &str = "1.3.6.1.4.1.311.76.8.1";
    /// Client authentication.
    pub const CLIENT_AUTHENTICATION: &str = "1.3.6.1.5.5.7.3.2";
    /// Lifetime signing.
    pub const LIFETIME_SIGNING: &str = "1.3.6.1.4.1.311.10.3.13";
    /// Any purpose.
    pub const ANY_PURPOSE: &str = "2.5.29.37.0";
    /// DNS server trust.
    pub const DOMAIN_NAME_SYSTEM_SERVER_TRUST: &str = "1.3.6.1.4.1.311.64.1.1";
    /// OEM Windows system component verification.
    pub const OEM_WINDOWS_SYSTEM_COMPONENT_VERIFICATION: &str = "1.3.6.1.4.1.311.10.3.7";
    /// Subject key identifier.
    pub const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
    /// MAC address.
    pub const MAC_ADDRESS: &str = "1.3.6.1.1.1.1.22";
    /// Authority key identifier.
    pub const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
    /// DSA.
    pub const DSA: &str = "1.2.840.10040.4.1";
    /// RSA.
    pub const RSA: &str = "1.2.840.113549.1.1.1";
    /// Elliptic curve public key.
    pub const EC: &str = "1.2.840.10045.2.1";
    /// User principal name.
    pub const USER_PRINCIPAL_NAME: &str = "1.3.6.1.4.1.311.20.2.3";
}
