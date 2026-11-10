use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use {
    ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey as EdEncodePrivateKey},
    rsa::{
        RsaPrivateKey,
        pkcs8::{EncodePrivateKey as RsaEncodePrivateKey, LineEnding},
        rand_core::{CryptoRng, Error as RngError, RngCore},
    },
    zeroize::Zeroizing,
};

use super::*;

struct TestRng(u64);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64()).unwrap_or(0)
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let length = chunk.len();
            chunk.copy_from_slice(&bytes[..length]);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> std::result::Result<(), RngError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

const GO_AGE_EXAMPLE_IDENTITY: &str =
    "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU";
const GO_AGE_EXAMPLE_PAYLOAD: &str = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA4aHJsTStaQkczRGQ0ZkYyK2E1ODN6ZFRJV0RrOC9SNDFrQ1lac3Z3VFc0CnlPNFBZZGxNV0RKK0N4Z1VOUnFZNVowVC9tK2czRkNoNWpJeEdMYkNWWGMKLS0tIEkvaW1ldlp6eTgxMjBKU3ptSm5tbi9LTWszcDVBMTFWODNOazQxbTlOUEUKcMXlNiShUgdT+Sxa0Q7KsnO6TWEXgHcT6DggQXod8soIGCJyyPhchXc0oTEaO3XpjQ6v";
const CLI_SECRET_KEY: &str =
    "AGE-SECRET-KEY-1M0J706Z6QXT0A4ALWZ098Q5AFLTWXCVXLFT8VFYAG24MXX56CUSQQLCA3H";
const CLI_PAYLOAD_1: &str = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4QVZQeDY5YnVaNERmYnVNSDJ3bE9jMG4rWGlyK0RXbEFHakVGYlJsbW53ClhRaUJzS0phTDJLMWFMallaam10N2RNd2x6cTE2Mk9ISGtET1JmbFYra1EKLS0tIFJhTkJpU0xyQ25xRGNhQW96R1YrSlhCanlYWG0vVmNNdVpGNnJPajQwUnMKWdqnjYaTQdZHJ4vU5m48rxY9m/feGXQbvDhfnEono6YNIU7YhHRZdIenn15m+nzufZTvLcPSVdRhYj1SGQosrskc";
const CLI_PAYLOAD_2: &str = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSByTU9DWVN5SFZiNE5jWFhBVzMra0JGYzZlK29lMzM5ODREcTVaN3VjdzNNClNpbTNKYm02bHpFY2lXeFVUd0t5MnpjTml1Ym5aR2cvU2dlT1ppM1llY2MKLS0tIGVSN3B4MUt3L00zZzMrWjdNZlJqc0d0bm5EMDlBVHNNenVYaGxWMXE3blEKIuhmz81/1hNsZOAi63+EhgKhrNODrRz96pphv5w3uPb8ljqcEU599CfUPhCBlRWmRQ6mXMMgnpHXjoT5Y9TLnQOKl+7cbE5MV1vUzOX/8oWqz1NWtOyZUICPe3g=";
const CLI_PAYLOAD_3: &str = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBSTzdUM2VYYTZjbDdnQkFvbmRZR0pIYkRwSkJMc3J5RW5iUDg0RGU1aFhRCnZCSXdnVlFaUnkvNE5sZHVCQmlXenRUcDBPb0xwbTJrTmhQM2xtMjlJUlEKLS0tIHZRQTdzN1llRElIZDI1bHVIQlpiemd6K1JzTWk3aXU4cGZnUjBCaXphenMKtxIeSLnUtuTxpXxfNRguEaHZ2yxpsfubTP2cLuXdEuOlAfDLKbMkletOZH4wspvIYZY+t91v+lXQ215pDH7n+bl4ixMB5W90";
const SSH_ED25519_PUBLIC: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1t0ub2F9lTZ6t6m5yNsWfkMie4XDT+6H7SHJDdBPp3 dev@dev-atom";
const SSH_ED25519_PRIVATE: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACAdbdLm9hfZU2erepucjbFn5DInuFw0/uh+0hyQ3QT6dwAAAJAEIfZOBCH2\n\
TgAAAAtzc2gtZWQyNTUxOQAAACAdbdLm9hfZU2erepucjbFn5DInuFw0/uh+0hyQ3QT6dw\n\
AAAEBVhCL+YcUCguYWCNrEw0bRNUG17Lnm8V/pton1IvKKqx1t0ub2F9lTZ6t6m5yNsWfk\n\
Mie4XDT+6H7SHJDdBPp3AAAADGRldkBkZXYtYXRvbQE=\n\
-----END OPENSSH PRIVATE KEY-----\n";

const ENCRYPTED_ED25519_PUBLIC: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKs7TTH9R2uBYx1ZN+KmQq8ZCw9SL1KPdVPq22y4TxTm encrypted-age-test";
const ENCRYPTED_ED25519_PRIVATE: &str = r"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDaJA7LI6
3c71klaIehXhCEAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIKs7TTH9R2uBYx1Z
N+KmQq8ZCw9SL1KPdVPq22y4TxTmAAAAoKkDzdeOxeQgHrQ+5t2umQAM2JmSdoxUw4S10B
iUKgHMv4R2hHvfTlA+jkwGg3tOxtRn6YqOZManfmcrDXW2W3xOep3pn0B6Zt5Ym7poupeY
SNGHwOkloSMUL0HAnT6hQMyG/ozLMZBrmKRl1cTNZaMVrzqaWq+0/3+DWfECWGFiJUMVX0
HhEHIwdOTDZ5sZxH3J5n+oTQAyoXnVgvHZNB8=
-----END OPENSSH PRIVATE KEY-----";
const ENCRYPTED_RSA_PUBLIC: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4zv3zpuRJx48i975a6JCS25CtCNny66hqentE2MPaAqxfh1jkuDh04XZkgvyIaICIy/zYMyjCGECq0OgeVJU9iCxdLJu/qvR2l4p8d+gSalftTtBHJDIPKUvzhN4u9pYixsul3bnRKQG5XJGVNRXCZ3hVaAmpjwGuXAytXUj8tCRbbcB4umvnA4EFr6vv7YrZJwvW2EzDopSOBgioMn/M0+lvDBvegDswa0LXFEV2wwGNoZf1u2XqO4TaI+GKtqxsqgPQBYkLfKaFdG85PNn9fK/OyB9Cy5+rwvdvDb8QxtC2TLmil+NH5ixhzOr0xx//JmlAXYi1rKpclcSQxvq/ encrypted-age-test";
const ENCRYPTED_RSA_PRIVATE: &str = r"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBYZ5b+Ir
ohv4nDtFMyvvt3AAAAGAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQC4zv3zpuRJ
x48i975a6JCS25CtCNny66hqentE2MPaAqxfh1jkuDh04XZkgvyIaICIy/zYMyjCGECq0O
geVJU9iCxdLJu/qvR2l4p8d+gSalftTtBHJDIPKUvzhN4u9pYixsul3bnRKQG5XJGVNRXC
Z3hVaAmpjwGuXAytXUj8tCRbbcB4umvnA4EFr6vv7YrZJwvW2EzDopSOBgioMn/M0+lvDB
vegDswa0LXFEV2wwGNoZf1u2XqO4TaI+GKtqxsqgPQBYkLfKaFdG85PNn9fK/OyB9Cy5+r
wvdvDb8QxtC2TLmil+NH5ixhzOr0xx//JmlAXYi1rKpclcSQxvq/AAAD0Lcsr+1psami7y
HW4k0xjlS33WA2phSwfBkDFgkPEh4W0CYLV3d7qaARV8e3bRxZpFEFpVYrBrzZ2KPZQjwk
C+Hh0BuXtVwvTtSJFpwo9JoZTclK8zf00mykwWv0ydulF/4kZ+cyFZJYayrbMzOgvtQEa0
UzJv+haMSiKvfMvRHnhIvac2MJ+hyp/YVzn6lxPiYMGX1gnTfV24i9dmZfa6DpWUc0YJna
moRq8GkqXnIfUDoiRhlcJPWPgChyrO5+NvyKT7rYamG7QRTnxwbH989LQigYJcmqnhwBy9
7LhsS5StPiaN2dEyxdR15GO03kCIOAf7OKvFxbRL0X1AlVlxF9Q98uWTKNIDyPDsZcAvgW
2ELTPv5SEX/NEICS7k9gmiVdtuKxDaw30ugGb8wCQJaC9yBHL5ag8PhP0WimulP5QRJ8kG
GxShOIKg36MduhP+RNgnEL8AXiKXmZMqQjILXD4Af73Jg6t23icg2ZsRdeLZv0E/iTWAnJ
+d525fm+f2iFo0PAjNFZvafxyuZ4RVikcIe4UFOj5fzuA7AdLsCW+JbohLTWyDd9ok1kki
kp/hd/TsO3bSv6nvKxy5perwN2+m3+KvO2PCarfM4CJaPZsueAtjveswHN/VYFAb/1rql7
e9kPg2MY/EMh0x3YtfVodeUW+aFRiqvPdxn/vkk8Kq5GJGJ/tM82dnNYv3klLBqLjJsWYd
5BZ5Xkl8XsoIl6cch5A9mXioBrlTojb3Dz4fAxAf4nCXp8/u9Q0nnHeml3FmKIrf8pWlP1
S1QKi0MY+TlLW/CLX7f4crAcqfDBljEEosoq7x460YRfHbWoEPHSZS35hao0gBbBdpInHD
aOFeXYAq7w0LXNQhHQFA2+dFpCP4YGjPi866+2hmkfZPMi8uPHqZfOjlna26kvJSN8V2x9
HaVBMglFVuxCas5yTCpwPCsBjdnu1WyMuK9WL0E36b9nsAwqTidhMv0CsDgtU6EhjBlikP
DKrf0Ex1oOo1bUDFRDQXc5elLZx8CnlB+HPN0eYBScAWJTEXPPxoIaOoKWSHOM6IUFgv2I
vOW58ft3wkYBE84FJIjJ9B67Gh3ZmQlTliouK4CMP9WbNws+ONTNa2xqXXlwpcJD1mBdLc
dDkT+YTF+s2zHg9qj+C/RW+2FFDRhtYJ3Hf977WlvfyF2KaPiyrzn63BBzSqK89bhRQq9K
CEgYso034bSt1kpxXkfdWvBg2RvRpWiKM0ObbpCw5QseEI6YFA45qNcB5XWQL9sdtB9b6M
URvR1YlqCDj291pFOcAxQGTbZEXx4=
-----END OPENSSH PRIVATE KEY-----";
const ENCRYPTED_CBC_PUBLIC: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2CmMz8a8NmRKdvMohzag2Hnnv+8112n/9GoBt8Ne7I encrypted-age-cbc-test";
const ENCRYPTED_CBC_PRIVATE: &str = r"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABBtpqFNu7
VaiyZe/8dNZ4ctAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJ2CmMz8a8NmRKdv
Mohzag2Hnnv+8112n/9GoBt8Ne7IAAAAoLUsPjFegZqLv65xYlVS+XhSVYkASrzercMk5N
Mjxm4cnehWv1uYKONg7MnnTQE17LvZwLTOPxbbvZYmmsATLZq06RW02QvQwyDt0AtvF8vf
5VeRUH24p7Fa6DXL+SrGpdkkrk718cEfG0Q+UViofzWXgU0+hMeUbUl9hDVR1snapPY1o0
4sfggAET6QuL3iybdCdtH5zucjH6Cv9bQI5RQ=
-----END OPENSSH PRIVATE KEY-----";
const LEGACY_RSA_PUBLIC: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCd3poVW8FgAJ5t8dQbrKP0xbipEPSP1p8Crhsbx9rgegR09g44xHrLYx3oRV5/Yb2q8J6G0RzOSQnkIRSDPHph/FZkTr+oBZohAHT3FjqWDYu6KQyAmOb8gN5RJxAn5c8Ym6NOWKuQEP6N6Lr4YMqKzBt++EUiFkSITa2LtyiSdJ/NcPeiZF2BW3T8NUfX6EfkObKSLLX+RB+mrKAGUaGyg+SuYKMYP8S5J/3Y+iJVd7qMQteaZWBHzTwsQyfxW8991ASnumcGGV73HIkx0yzYvpL4V91i7vq7PhVsMBESDjK0MnOrZaCPkXpVlSl4Z75ByuxO5NBtGt0/7FKYz8Nh";
const LEGACY_RSA_PRIVATE: &str = r"-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,31758A41151960D0173D53F782BFFE80

tSy8EaS3OBWtC50jOt08KyQLqqive+Pdp0UWHUgvENUaqRtGA574+pjdP/i/Yc5l
fZr9geuL5bZKNBtFKwQbW1yu8eQri9XlLISNKhNgCWH+pqujOvVlvvIPSoR0Vdcv
j3L+KMlnPcfY8djV/EvEbGrJYxxN02oBEIvsk/TR350Lt7no1MUi6dLhfF4KB/b3
wvKP4hQgWJkZB+q+MMxSum/VeDw15/CTHpoGgCiBY4BcLQe+KAs4WTuKSEbE+imL
oWNrkBphIMzkV/HihSkWdpZ3NUNQJC6fTGmdkh/dNIlMREwk/2kFsRbmaUXuyRyK
NyvhaSBb7xOa7BiS1fnnXsB5fi8nS36rsY6INi+N9N0adArVil3vKuWpZWuteOjx
/74O4ECiMThduQ+f011W/+JmSvtz2z3yChrpVCwq2ojv5hb4tMgDykl4emyZiQb6
4exvMKujufqj8bo0BQ0qQ+PNTVYKYBU/V44keZdxfqkZBJ7ay5fdEFP+6aDCQeZ8
S0UIExxh5NXV+zBFuRKPGSO07CpIZYQMlV7z79NedjhJHMv7zn3S+l4dX5lezT5F
WyiCzLb3peHfp10lpqYNxdqIEnziGncIKIywwBGQQ5TevfyOcaYRLnV40waTt4hw
9jySrnCi8L0BpiURu6JXgxLKgqcHLiuieNTiXiujBCSYdUnRB9rJk/eWMCU7zBD2
P3pyhBBycvbXr1Dm8SyM8KZPBgm54l5qpPo6LE62slbdnJ+8/Iz/zmRF4HgWLEc1
d11LfrXocxTCBIV9hAw+0CobCFNN6j0uFxdN24cNfAnx35C3n11iPehF4B6Gw3m7
wdjbUqsni7Ryc0yP3XTm/C8zBJzNe28qpM2+IeDnT95VQTf1FI+0tPNHcz5zQcEt
CjyWqNDF3wBVxSYGmn125s6XQ5eYusmNiBXdAwwPWwNA1DWAfbCgm7rlJJdenDfK
QkYcLg+CQCVvbXkbA0u38AEF3WbHzBaPgne4Xhfam77ifjFg/NY+tzwna7YHy+JC
Tv8xn3XXclenikmAU/xhDqUowIyJeDBxcKIQVDawsLe7YBgOyEIe/VjI13VRMeUu
3vRnmo8X+aaUCfABxRW5VPS3eyAAM+isL1UygkMJM2ueAb7j0WbwUNOa/vonO9IJ
y8JoeJgG0qqizU1Wl1YjHSUcTcw3EBRDfyeGsKGVVlufVEC/RfuhUn45VWkeOq29
5fcylr7bw3X/LsJwFPypjHFHEUJD2JDvPUssgXhrD5t3DgQPv//9u5ndngHnDhrd
Rzu9w8WL87lRHt5/zvaTaTx1/SSzY2BcID44dC7O/Ap5Cgtmm8y/r7x2x6cxyj+7
Icl7FCnoQg/cQv1B7OkEnAUOw/hzmrsui7dwJXC1Zleoli3XbtSG1dIB1lmhe4nD
bThRkaaGq9NUG1+dSau6siXmGQbtOuz/5KReVsDj5eeDM6VjqQjVUaPeizI4DBEl
sXpysemrIiiMNXpInB8nNvZFgBKv8mBMcBJG7k6icxJLAcgrOKtm+e5zOe3Ke+Yx
MkrcMULaZBsnjadWzmmJJ8h0ngOt8FzVVPy1Gh0bIBQgTadgNJFDnLav0VteLBys
-----END RSA PRIVATE KEY-----";

fn decode_fixture(value: &str) -> Vec<u8> {
    STANDARD.decode(value).expect("fixture base64")
}

#[test]
fn go_example_fixture_decrypts() {
    let identity = AgeIdentity::from_private_key(GO_AGE_EXAMPLE_IDENTITY).expect("identity");
    let plaintext = AgeFile::decrypt(&decode_fixture(GO_AGE_EXAMPLE_PAYLOAD), &[identity])
        .expect("decrypt fixture");
    assert_eq!(plaintext, b"Black lives matter.");
}

#[test]
fn cli_fixtures_decrypt() {
    let cases = [
        (
            CLI_PAYLOAD_1,
            "value from age cli generated keys\n".as_bytes(),
        ),
        (
            CLI_PAYLOAD_2,
            "cli interoperability payload #2\nwith newline\nand third line\n".as_bytes(),
        ),
        (
            CLI_PAYLOAD_3,
            "binary\0\x01\x02 with emoji ✅ and spaces end\n".as_bytes(),
        ),
    ];
    for (payload, expected) in cases {
        let identity = AgeIdentity::from_private_key(CLI_SECRET_KEY).expect("identity");
        let plaintext = AgeFile::decrypt(&decode_fixture(payload), &[identity]).expect("decrypt");
        assert_eq!(plaintext, expected);
    }
}

#[test]
fn native_key_hrp_case_is_significant() {
    let key = AgeKey::generate().expect("key");
    assert!(AgeRecipient::from_public_key(key.public_key.to_ascii_uppercase()).is_err());
    assert!(AgeIdentity::from_private_key(key.private_key.to_ascii_lowercase()).is_err());
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    assert_eq!(recipient.to_public_key().expect("public"), key.public_key);
    assert_eq!(identity.to_private_key().expect("private"), key.private_key);
    assert!(!format!("{key:?}").contains(&key.private_key));
}

#[test]
fn matching_but_malformed_stanzas_are_fatal() {
    let key = AgeKey::generate().expect("key");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let stanza = Stanza::new("X25519", ["AA", "extra"], [0u8; 32]);
    assert!(identity.file_key_from_stanzas(&[stanza]).is_err());
    let low_order = Stanza::new("X25519", [crate::codec::encode_raw(&[0u8; 32])], [0u8; 32]);
    assert!(identity.file_key_from_stanzas(&[low_order]).is_err());
}

#[test]
fn detached_header_and_injected_file_key_round_trip() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let encrypted = AgeFile::encrypt(b"detached header", &[recipient]).expect("encrypt");
    let header = AgeFile::extract_header(&encrypted).expect("header");
    let file_key =
        AgeFile::decrypt_header(&header, std::slice::from_ref(&identity)).expect("header key");
    let injected = AgeIdentity::from_file_key(file_key.as_slice()).expect("injected key");
    assert_eq!(
        AgeFile::decrypt(&encrypted, &[injected]).expect("decrypt"),
        b"detached header"
    );
}

#[test]
fn native_round_trips_empty_and_large_payloads() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    for plaintext in [
        Vec::new(),
        vec![b'a'; 64 * 1024],
        vec![b'a'; 64 * 1024 + 17],
        vec![b'a'; 128 * 1024],
    ] {
        let encrypted =
            AgeFile::encrypt(&plaintext, std::slice::from_ref(&recipient)).expect("encrypt");
        let decrypted =
            AgeFile::decrypt(&encrypted, std::slice::from_ref(&identity)).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }
}

#[test]
fn known_secret_has_known_public_key() {
    let secret = [0u8; 32];
    let public = bech32::encode("age", &x25519_base_for_test(&secret)).expect("public key");
    assert_eq!(
        public,
        "age19ljhmg68e43yx9fgm2k9lwefquc0la5y4lzvlshdjzv47kxt8d6qr9vf4p"
    );
}

fn x25519_base_for_test(secret: &[u8; 32]) -> [u8; 32] {
    super::crypto::x25519_base(secret)
}

#[test]
fn scrypt_and_armor_round_trip() {
    let recipient = AgeRecipient::from_passphrase("correct horse", 4).expect("recipient");
    let identity = AgeIdentity::from_passphrase("correct horse").expect("identity");
    let encrypted = AgeFile::encrypt(b"passphrase payload", &[recipient]).expect("encrypt");
    assert!(encrypted.starts_with(b"age-encryption.org/v1\n-> scrypt "));
    assert_eq!(
        AgeFile::decrypt(&encrypted, &[identity]).expect("decrypt"),
        b"passphrase payload"
    );
    let armored = AgeFile::encrypt_armored(
        &[b'z'; 200],
        &[AgeRecipient::from_passphrase("pw", 4).expect("recipient")],
    )
    .expect("armor");
    assert!(armored.starts_with(AgeArmor::BEGIN));
    assert!(
        AgeFile::decrypt_armored(
            &armored,
            &[AgeIdentity::from_passphrase("pw").expect("identity")],
        )
        .is_ok()
    );
}

#[test]
fn scrypt_rejects_wrong_passphrase_and_invalid_work_factor() {
    let recipient = AgeRecipient::from_passphrase("right", 4).expect("recipient");
    let encrypted = AgeFile::encrypt(b"x", &[recipient]).expect("encrypt");
    assert!(
        AgeFile::decrypt(
            &encrypted,
            &[AgeIdentity::from_passphrase("wrong").expect("identity")],
        )
        .is_err()
    );
    assert!(AgeRecipient::from_passphrase("", 4).is_err());
    assert!(AgeRecipient::from_passphrase("pw", 0).is_err());
    assert!(AgeRecipient::from_passphrase("pw", 31).is_err());
    assert!(AgeRecipient::from_passphrase("pw", 19).is_ok());
    assert!(AgeIdentity::from_passphrase("").is_err());
    let capped = AgeIdentity::from_passphrase("right")
        .expect("identity")
        .with_max_scrypt_work_factor(3)
        .expect("cap");
    assert!(matches!(
        AgeFile::decrypt(&encrypted, &[capped]),
        Err(AgeError::ScryptWorkFactorTooLarge(4))
    ));
    let default = AgeIdentity::from_passphrase("right").expect("identity");
    assert!(AgeFile::decrypt(&encrypted, &[default]).is_ok());
}

#[test]
fn armor_rejects_long_body_lines() {
    let armored = AgeArmor::encode(b"age-encryption.org/v1\n");
    let mut lines: Vec<String> = armored.lines().map(str::to_owned).collect();
    lines[1] = "A".repeat(65);
    let tampered = format!("{}\n", lines.join("\n"));
    assert!(AgeArmor::decode(&tampered).is_err());
}

#[test]
fn file_api_round_trips() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let stem = std::env::temp_dir().join(format!("neotales-age-test-{}", std::process::id()));
    let input = stem.with_extension("plain");
    let encrypted = stem.with_extension("age");
    let output = stem.with_extension("out");
    std::fs::write(&input, b"file api").expect("write input");
    AgeFile::encrypt_file(&input, &encrypted, std::slice::from_ref(&recipient))
        .expect("encrypt file");
    AgeFile::decrypt_file(&encrypted, &output, std::slice::from_ref(&identity))
        .expect("decrypt file");
    assert_eq!(std::fs::read(&output).expect("read output"), b"file api");
    let _ = std::fs::remove_file(input);
    let _ = std::fs::remove_file(encrypted);
    let _ = std::fs::remove_file(output);

    let same_path = stem.with_extension("same");
    std::fs::write(&same_path, b"preserve me").expect("write same-path input");
    assert!(AgeFile::encrypt_file(&same_path, &same_path, &[recipient]).is_err());
    assert_eq!(
        std::fs::read(&same_path).expect("read same-path input"),
        b"preserve me"
    );
    let _ = std::fs::remove_file(same_path);
}

#[test]
fn encrypts_to_multiple_recipients() {
    let first = AgeKey::generate().expect("first key");
    let second = AgeKey::generate().expect("second key");
    let recipients = [
        AgeRecipient::from_public_key(&first.public_key).expect("first recipient"),
        AgeRecipient::from_public_key(&second.public_key).expect("second recipient"),
    ];
    let encrypted = AgeFile::encrypt(b"many recipients", &recipients).expect("encrypt");
    for key in [&first, &second] {
        let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
        assert_eq!(
            AgeFile::decrypt(&encrypted, &[identity]).expect("decrypt"),
            b"many recipients"
        );
    }
}

#[test]
fn ssh_ed25519_fixture_round_trips() {
    let recipient = AgeRecipient::from_ssh_public_key(SSH_ED25519_PUBLIC).expect("recipient");
    let identity = AgeIdentity::from_ssh_private_key(SSH_ED25519_PRIVATE).expect("identity");
    let encrypted = AgeFile::encrypt(b"ed25519 recipient", &[recipient]).expect("encrypt");
    assert_eq!(
        AgeFile::decrypt(&encrypted, &[identity]).expect("decrypt"),
        b"ed25519 recipient"
    );
}

#[test]
fn ssh_authorized_key_options_and_ed25519_pkcs8_are_supported() {
    let signing = SigningKey::from_bytes(&[42u8; 32]);
    let public = SshEd25519Key::export_public_key(&signing.to_bytes()).expect("public");
    let with_options = format!("no-pty,command=\"true\"\t{public}\tcomment");
    let recipient = AgeRecipient::from_ssh_public_key(&with_options).expect("recipient");
    let pem = <SigningKey as EdEncodePrivateKey>::to_pkcs8_pem(&signing, LineEnding::LF)
        .expect("PKCS#8 PEM");
    let identity = AgeIdentity::from_ssh_private_key(pem.as_str()).expect("identity");
    let encrypted = AgeFile::encrypt(b"PKCS#8 Ed25519", &[recipient]).expect("encrypt");
    assert_eq!(
        AgeFile::decrypt(&encrypted, &[identity]).expect("decrypt"),
        b"PKCS#8 Ed25519"
    );
}

#[test]
fn rejects_tampering_and_bad_armor() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let mut encrypted =
        AgeFile::encrypt(b"hello", std::slice::from_ref(&recipient)).expect("encrypt");
    let last = encrypted.len() - 1;
    encrypted[last] ^= 1;
    assert!(AgeFile::decrypt(&encrypted, std::slice::from_ref(&identity)).is_err());

    let armored = AgeFile::encrypt_armored(b"hello", &[recipient]).expect("armor");
    assert!(AgeFile::decrypt_armored(&format!("{armored}junk"), &[identity]).is_err());
}

#[test]
fn rejects_mixed_scrypt_recipient() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let passphrase = AgeRecipient::from_passphrase("pw", 4).expect("passphrase");
    assert!(AgeFile::encrypt(b"x", &[passphrase, recipient]).is_err());
}

#[test]
fn ssh_rsa_round_trips() {
    let private = RsaPrivateKey::new(&mut TestRng(0x1234_5678_9abc_def0), 2048).expect("RSA key");
    let public_line = SshRsaKey::export_public_key(&private.to_public_key()).expect("public line");
    let recipient = AgeRecipient::from_ssh_public_key(&public_line).expect("recipient");
    let pem = <RsaPrivateKey as RsaEncodePrivateKey>::to_pkcs8_pem(&private, LineEnding::LF)
        .expect("private PEM");
    let identity = AgeIdentity::from_ssh_private_key(&pem).expect("identity");
    let encrypted = AgeFile::encrypt(b"ssh rsa recipient", &[recipient]).expect("encrypt");
    assert_eq!(
        AgeFile::decrypt(&encrypted, &[identity]).expect("decrypt"),
        b"ssh rsa recipient"
    );
}

#[test]
fn enforces_read_limits() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let encrypted = AgeFile::encrypt(b"payload-limit", &[recipient]).expect("encrypt");
    assert!(
        AgeFile::decrypt_with_options(
            &encrypted,
            std::slice::from_ref(&identity),
            AgeReadOptions::default().with_max_header_bytes(32),
        )
        .is_err()
    );
    assert!(
        AgeFile::decrypt_with_options(
            &encrypted,
            std::slice::from_ref(&identity),
            AgeReadOptions::default().with_max_payload_bytes(4),
        )
        .is_err()
    );
}

#[test]
fn rejects_padded_header_mac_base64() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let encrypted = AgeFile::encrypt(b"padded mac", &[recipient]).expect("encrypt");
    let footer = encrypted
        .windows(4)
        .position(|window| window == b"--- ")
        .expect("footer");
    let line_end = encrypted[footer..]
        .iter()
        .position(|value| *value == b'\n')
        .map(|offset| footer + offset)
        .expect("footer newline");
    let mac = STANDARD_NO_PAD
        .decode(&encrypted[footer + 4..line_end])
        .expect("MAC base64");
    let mut padded = encrypted[..footer].to_vec();
    padded.extend_from_slice(b"--- ");
    padded.extend_from_slice(STANDARD.encode(&mac).as_bytes());
    padded.push(b'\n');
    padded.extend_from_slice(&encrypted[line_end + 1..]);
    assert!(AgeFile::decrypt(&padded, &[identity]).is_err());
}

#[test]
fn truncated_header_and_bad_mac_are_rejected() {
    let key = AgeKey::generate().expect("key");
    let recipient = AgeRecipient::from_public_key(&key.public_key).expect("recipient");
    let identity = AgeIdentity::from_private_key(&key.private_key).expect("identity");
    let encrypted = AgeFile::encrypt(b"hello", &[recipient]).expect("encrypt");
    assert!(AgeFile::decrypt(&encrypted[..20], std::slice::from_ref(&identity)).is_err());
    let mut bad_mac = encrypted.clone();
    let marker = bad_mac
        .windows(4)
        .position(|window| window == b"--- ")
        .expect("footer");
    let mac_start = marker + 4;
    bad_mac[mac_start] = if bad_mac[mac_start] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert!(AgeFile::decrypt(&bad_mac, &[identity]).is_err());
}

#[test]
fn encrypted_ed25519_identity_is_lazy_and_cached() {
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = Arc::clone(&calls);
    let identity = AgeIdentity::from_encrypted_ssh_private_key(
        ENCRYPTED_ED25519_PUBLIC,
        ENCRYPTED_ED25519_PRIVATE,
        move || {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(b"ed-passphrase".to_vec()))
        },
    )
    .expect("encrypted identity");
    let recipient = identity.recipient().expect("recipient");
    let encrypted = AgeFile::encrypt(b"encrypted ed25519", &[recipient]).expect("encrypt");
    assert_eq!(
        AgeFile::decrypt(&encrypted, std::slice::from_ref(&identity)).expect("decrypt"),
        b"encrypted ed25519"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        AgeFile::decrypt(&encrypted, std::slice::from_ref(&identity)).expect("cached decrypt"),
        b"encrypted ed25519"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!format!("{identity:?}").contains("ed-passphrase"));
    assert!(!format!("{identity:?}").contains("BEGIN OPENSSH"));
}

#[test]
fn encrypted_identity_does_not_prompt_for_another_recipient() {
    let other = AgeKey::generate().expect("other key");
    let other_recipient = AgeRecipient::from_public_key(&other.public_key).expect("recipient");
    let encrypted = AgeFile::encrypt(b"other", &[other_recipient]).expect("encrypt");
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = Arc::clone(&calls);
    let identity = AgeIdentity::from_encrypted_ssh_private_key(
        ENCRYPTED_ED25519_PUBLIC,
        ENCRYPTED_ED25519_PRIVATE,
        move || {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(b"ed-passphrase".to_vec()))
        },
    )
    .expect("identity");
    assert!(matches!(
        AgeFile::decrypt(&encrypted, &[identity]),
        Err(AgeError::NoMatchingIdentity)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn encrypted_ed25519_identity_rejects_wrong_passphrase_and_callback_errors() {
    let recipient = AgeRecipient::from_ssh_public_key(ENCRYPTED_ED25519_PUBLIC).expect("recipient");
    let encrypted = AgeFile::encrypt(b"secret", std::slice::from_ref(&recipient)).expect("encrypt");
    let wrong = AgeIdentity::from_encrypted_ssh_private_key(
        ENCRYPTED_ED25519_PUBLIC,
        ENCRYPTED_ED25519_PRIVATE,
        || Ok(Zeroizing::new(b"wrong".to_vec())),
    )
    .expect("identity");
    assert!(AgeFile::decrypt(&encrypted, &[wrong]).is_err());

    let callback_error = AgeIdentity::from_encrypted_ssh_private_key(
        ENCRYPTED_ED25519_PUBLIC,
        ENCRYPTED_ED25519_PRIVATE,
        || Err(AgeError::Crypto("callback failed")),
    )
    .expect("identity");
    assert!(AgeFile::decrypt(&encrypted, &[callback_error]).is_err());
}

#[test]
fn encrypted_rsa_identity_round_trips_and_checks_public_key() {
    let identity = AgeIdentity::from_encrypted_ssh_private_key(
        ENCRYPTED_RSA_PUBLIC,
        ENCRYPTED_RSA_PRIVATE,
        || Ok(Zeroizing::new(b"rsa-passphrase".to_vec())),
    )
    .expect("identity");
    let recipient = identity.recipient().expect("recipient");
    let encrypted = AgeFile::encrypt(b"encrypted rsa", &[recipient]).expect("encrypt");
    assert_eq!(
        AgeFile::decrypt(&encrypted, &[identity]).expect("decrypt"),
        b"encrypted rsa"
    );

    let mismatch = AgeIdentity::from_encrypted_ssh_private_key(
        ENCRYPTED_ED25519_PUBLIC,
        ENCRYPTED_RSA_PRIVATE,
        || Ok(Zeroizing::new(b"rsa-passphrase".to_vec())),
    )
    .expect("mismatched identity");
    let ed_recipient =
        AgeRecipient::from_ssh_public_key(ENCRYPTED_ED25519_PUBLIC).expect("recipient");
    let mismatched_file = AgeFile::encrypt(b"mismatch", &[ed_recipient]).expect("encrypt");
    assert!(AgeFile::decrypt(&mismatched_file, &[mismatch]).is_err());
}

#[test]
fn encrypted_openssh_cbc_and_legacy_pem_round_trip() {
    let cbc = AgeIdentity::from_encrypted_ssh_private_key(
        ENCRYPTED_CBC_PUBLIC,
        ENCRYPTED_CBC_PRIVATE,
        || Ok(Zeroizing::new(b"cbc-passphrase".to_vec())),
    )
    .expect("CBC identity");
    let cbc_recipient = cbc.recipient().expect("recipient");
    let cbc_file = AgeFile::encrypt(b"cbc", &[cbc_recipient]).expect("encrypt");
    assert_eq!(
        AgeFile::decrypt(&cbc_file, &[cbc]).expect("CBC decrypt"),
        b"cbc"
    );

    let legacy =
        AgeIdentity::from_encrypted_ssh_private_key(LEGACY_RSA_PUBLIC, LEGACY_RSA_PRIVATE, || {
            Ok(Zeroizing::new(b"legacy-passphrase".to_vec()))
        })
        .expect("legacy identity");
    let legacy_recipient = legacy.recipient().expect("recipient");
    let legacy_file = AgeFile::encrypt(b"legacy", &[legacy_recipient]).expect("encrypt");
    assert_eq!(
        AgeFile::decrypt(&legacy_file, &[legacy]).expect("legacy decrypt"),
        b"legacy"
    );
}

#[test]
fn encrypted_openssh_reports_embedded_public_key_and_rejects_unencrypted_pem() {
    let error = AgeIdentity::from_ssh_private_key(ENCRYPTED_ED25519_PRIVATE)
        .expect_err("encrypted key should require a passphrase");
    match error {
        AgeError::PassphraseMissing { public_key } => {
            assert!(public_key.starts_with("ssh-ed25519 "));
            assert!(AgeRecipient::from_ssh_public_key(public_key).is_ok());
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(
        AgeIdentity::from_encrypted_ssh_private_key(
            ENCRYPTED_ED25519_PUBLIC,
            SSH_ED25519_PRIVATE,
            || Ok(Zeroizing::new(b"unused".to_vec())),
        )
        .is_err()
    );
}

#[test]
fn parse_identities_matches_age_reference_cases() {
    let valid = "\n# this is a comment\n# AGE-SECRET-KEY-1705XN76M8EYQ8M9PY4E2G3KA8DN7NSCGT3V4HMN20H3GCX4AS6HSSTG8D3\n#\n\nAGE-SECRET-KEY-1D6K0SGAX3NU66R4GYFZY0UQWCLM3UUSF3CXLW4KXZM342WQSJ82QKU59QJ\nAGE-SECRET-KEY-19WUMFE89H3928FRJ5U3JYRNHM6CERQGKSQ584AQ8QY7T7R09D32SWE4DYH";
    let identities = parse_identities(valid).expect("valid identities");
    assert_eq!(identities.len(), 2);
    let invalid = "\nAGE-SECRET-KEY-1705XN76M8EYQ8M9PY4E2G3KA8DN7NSCGT3V4HMN20H3GCX4AS6HSSTG8D3\nAGE-SECRET-KEY--1D6K0SGAX3NU66R4GYFZY0UQWCLM3UUSF3CXLW4KXZM342WQSJ82QKU59Q";
    let error = parse_identities(invalid).expect_err("invalid identities");
    assert!(error.to_string().contains("line 3"));
    assert!(parse_identities("# only comments\n").is_err());
    assert!(parse_identities(&"x".repeat(64 * 1024 + 1)).is_err());
}

#[test]
fn parse_recipients_hides_line_contents_and_checks_limits() {
    let key = AgeKey::generate().expect("key");
    let input = format!("# comment\n\n{}\n", key.public_key);
    assert_eq!(parse_recipients(&input).expect("recipients").len(), 1);
    let error = parse_recipients("not-a-recipient").expect_err("invalid recipient");
    assert_eq!(error.to_string(), "malformed recipient at line 1");
    assert!(parse_recipients("# comments only\n").is_err());
    assert!(parse_recipients(&"x".repeat(64 * 1024 + 1)).is_err());
}
