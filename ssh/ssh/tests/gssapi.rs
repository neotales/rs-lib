// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::cell::RefCell;
use std::rc::Rc;

use neotales_ssh::gssapi::{
    GssapiError, GssapiExchange, GssapiExchangeAction, GssapiExchangeComplete, GssapiExchangeState,
    GssapiMechanismResult, GssapiRequest, GssapiResponse, GssapiToken,
    GssapiTokenMechanismCallback, MAX_GSSAPI_EXCHANGES, MAX_GSSAPI_MECHANISM_LENGTH,
    MAX_GSSAPI_MECHANISMS, MAX_GSSAPI_TOKEN_LENGTH, SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
    SSH_MSG_USERAUTH_GSSAPI_RESPONSE, SSH_MSG_USERAUTH_GSSAPI_TOKEN,
};

/// PROVENANCE of the three byte vectors below: **from the specification**.
///
/// RFC 4462 gives the field layout for each message but no worked example, so
/// these are not RFC bytes either -- they are the RFC's layout filled in by
/// hand, with the string payloads `"mechanism"` and `"opaque"` standing in for
/// real DER-encoded OIDs and real GSS-API output. The claim being checked is the
/// framing, and the layouts are quoted so the claim can be read against its
/// source:
///
/// Section 3.3:
///
/// ```text
///    byte        SSH_MSG_USERAUTH_GSSAPI_RESPONSE
///    string      selected mechanism OID
/// ```
///
/// Section 3.4:
///
/// ```text
///    byte        SSH_MSG_USERAUTH_GSSAPI_TOKEN
///    string      data returned from either GSS_Init_sec_context()
///                or GSS_Accept_sec_context()
/// ```
///
/// Section 3.5:
///
/// ```text
///    byte      SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE
/// ```
///
/// The message numbers come from RFC 4462 section 5:
///
/// ```text
///    #define SSH_MSG_USERAUTH_GSSAPI_RESPONSE          60
///    #define SSH_MSG_USERAUTH_GSSAPI_TOKEN             61
///    #define SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE 63
/// ```
#[test]
fn response_token_and_exchange_complete_use_exact_rfc4462_framing() {
    let response = GssapiResponse::new(b"mechanism").encode().unwrap();
    assert_eq!(
        // `60`, then string "mechanism" with its four-byte length 9.
        response,
        vec![
            SSH_MSG_USERAUTH_GSSAPI_RESPONSE,
            0,
            0,
            0,
            9,
            b'm',
            b'e',
            b'c',
            b'h',
            b'a',
            b'n',
            b'i',
            b's',
            b'm',
        ]
    );
    assert_eq!(&response[5..], b"mechanism");

    let token = GssapiToken::new(b"opaque").encode().unwrap();
    assert_eq!(
        // `61`, then string "opaque" with its four-byte length 6.
        token,
        vec![
            SSH_MSG_USERAUTH_GSSAPI_TOKEN,
            0,
            0,
            0,
            6,
            b'o',
            b'p',
            b'a',
            b'q',
            b'u',
            b'e'
        ]
    );
    assert_eq!(&token[5..], b"opaque");

    let complete = GssapiExchangeComplete.encode().unwrap();
    // `63` and nothing else: RFC 4462 gives this message no fields.
    assert_eq!(complete, vec![SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE]);
    assert_eq!(
        GssapiExchangeComplete::decode(&complete),
        Ok(GssapiExchangeComplete)
    );
}

#[test]
fn framing_rejects_empty_required_fields_bounds_and_trailing_data() {
    assert!(matches!(
        GssapiResponse::decode(&[SSH_MSG_USERAUTH_GSSAPI_RESPONSE, 0, 0, 0, 0]),
        Err(GssapiError::EmptyField)
    ));
    assert!(matches!(
        GssapiToken::decode(&[SSH_MSG_USERAUTH_GSSAPI_TOKEN, 0, 0, 0, 0]),
        Err(GssapiError::EmptyField)
    ));
    assert!(matches!(
        GssapiExchangeComplete::decode(&[SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, 0,]),
        Err(GssapiError::InvalidMessage)
    ));
    assert!(matches!(
        GssapiResponse::decode(&[SSH_MSG_USERAUTH_GSSAPI_RESPONSE, 0, 0, 0, 1, b'x', 0,]),
        Err(GssapiError::InvalidMessage)
    ));

    assert!(matches!(
        GssapiResponse::new(vec![b'x'; MAX_GSSAPI_MECHANISM_LENGTH + 1]).encode(),
        Err(GssapiError::LimitExceeded)
    ));
    assert!(matches!(
        GssapiToken::new(vec![b'x'; MAX_GSSAPI_TOKEN_LENGTH + 1]).encode(),
        Err(GssapiError::LimitExceeded)
    ));
    assert!(matches!(
        GssapiRequest::new(Vec::<Vec<u8>>::new()).encode(),
        Err(GssapiError::EmptyField)
    ));
    assert!(matches!(
        GssapiRequest::new(vec![vec![b'x'; MAX_GSSAPI_MECHANISM_LENGTH + 1]]).encode(),
        Err(GssapiError::LimitExceeded)
    ));
}

#[test]
fn method_specific_request_uses_bounded_uint32_count_and_rejects_trailing_fields() {
    let request = GssapiRequest::new([b"one".as_slice(), b"two".as_slice()]);
    let encoded = request.encode().unwrap();
    assert_eq!(&encoded[..4], &[0, 0, 0, 2]);
    assert_eq!(GssapiRequest::decode(&encoded), Ok(request));

    let mut trailing = encoded;
    trailing.push(0);
    assert!(matches!(
        GssapiRequest::decode(&trailing),
        Err(GssapiError::InvalidMessage)
    ));

    let too_many = vec![b"x".to_vec(); MAX_GSSAPI_MECHANISMS + 1];
    assert!(matches!(
        GssapiRequest::new(too_many).encode(),
        Err(GssapiError::LimitExceeded)
    ));
}

#[test]
fn exchange_requires_response_tokens_and_acknowledgement_in_order() {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let seen_for_callback = Rc::clone(&seen);
    let mechanism = GssapiTokenMechanismCallback::new(b"mechanism", move |token: &[u8]| {
        seen_for_callback.borrow_mut().push(token.to_vec());
        if seen_for_callback.borrow().len() == 1 {
            GssapiMechanismResult::continue_with(b"reply")
        } else {
            GssapiMechanismResult::accept()
        }
    });
    let mut exchange = GssapiExchange::new(4).unwrap();

    let response = exchange.begin(b"mechanism").unwrap();
    assert_eq!(
        GssapiResponse::decode(&response).unwrap().mechanism(),
        b"mechanism"
    );
    let action = exchange
        .receive_token(&GssapiToken::new(b"first").encode().unwrap(), &mechanism)
        .unwrap();
    assert!(matches!(action, GssapiExchangeAction::SendToken(_)));
    assert_eq!(exchange.state(), GssapiExchangeState::AwaitingToken);

    let action = exchange
        .receive_token(&GssapiToken::new(b"second").encode().unwrap(), &mechanism)
        .unwrap();
    assert_eq!(action, GssapiExchangeAction::AwaitExchangeComplete);
    assert_eq!(
        exchange.state(),
        GssapiExchangeState::AwaitingExchangeComplete
    );
    assert_eq!(
        seen.borrow().as_slice(),
        vec![b"first".to_vec(), b"second".to_vec()]
    );

    exchange
        .receive_exchange_complete(&[SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE])
        .unwrap();
    assert_eq!(exchange.state(), GssapiExchangeState::Complete);
    assert!(exchange.is_complete());
    assert!(exchange.is_terminal());
    assert!(
        exchange
            .receive_exchange_complete(&[SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE])
            .is_err()
    );
}

#[test]
fn exchange_rejects_early_duplicate_and_bounded_continuation() {
    let mechanism = GssapiTokenMechanismCallback::new(b"mechanism", |_token| {
        GssapiMechanismResult::continue_with(b"again")
    });
    let mut early = GssapiExchange::new(2).unwrap();
    assert!(matches!(
        early.receive_token(&GssapiToken::new(b"token").encode().unwrap(), &mechanism),
        Err(GssapiError::InvalidState)
    ));
    assert_eq!(early.state(), GssapiExchangeState::Failed);

    let mut limited = GssapiExchange::new(1).unwrap();
    limited.begin(b"mechanism").unwrap();
    assert!(matches!(
        limited.receive_token(&GssapiToken::new(b"token").encode().unwrap(), &mechanism),
        Err(GssapiError::TooManyExchanges)
    ));
    assert_eq!(limited.state(), GssapiExchangeState::Failed);

    let mut duplicate = GssapiExchange::new(MAX_GSSAPI_EXCHANGES).unwrap();
    duplicate.begin(b"mechanism").unwrap();
    assert!(matches!(
        duplicate.begin(b"mechanism"),
        Err(GssapiError::InvalidState)
    ));
}

#[test]
fn callback_panics_and_unsupported_mechanisms_fail_closed_without_token_disclosure() {
    let panic_mechanism = GssapiTokenMechanismCallback::new(b"mechanism", |_token| {
        panic!("secret-token-must-not-escape")
    });
    let mut exchange = GssapiExchange::new(2).unwrap();
    exchange.begin(b"mechanism").unwrap();
    let error = exchange
        .receive_token(
            &GssapiToken::new(b"input").encode().unwrap(),
            &panic_mechanism,
        )
        .unwrap_err();
    assert_eq!(error, GssapiError::CallbackPanicked);
    assert_eq!(exchange.state(), GssapiExchangeState::Failed);
    assert!(!format!("{error:?}").contains("secret-token-must-not-escape"));
    assert!(!format!("{error}").contains("secret-token-must-not-escape"));
    assert!(!format!("{exchange:?}").contains("secret-token-must-not-escape"));

    let mut wrong = GssapiExchange::new(2).unwrap();
    wrong.begin(b"mechanism").unwrap();
    let error = wrong
        .receive_token(
            &GssapiToken::new(b"input").encode().unwrap(),
            &GssapiTokenMechanismCallback::new(b"other", |_token| GssapiMechanismResult::accept()),
        )
        .unwrap_err();
    assert_eq!(error, GssapiError::UnsupportedMechanism);
    assert_eq!(wrong.state(), GssapiExchangeState::Failed);
}
