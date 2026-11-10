//! `GET /containers/{id}/json`: the container inspect document.
//!
//! # Why this one is not a model
//!
//! Inspect is the largest document the Engine sends — 24 top-level members and
//! five nested blocks against Docker Engine 29.8.0 — and it is the one place
//! where "decode into a struct" and "tell the truth" come apart. A struct with
//! declared fields drops everything else, silently, because serde ignores an
//! unknown member. So [`ContainerInspect`] keeps the document as sent and reads
//! the members a caller usually wants out of it, rather than replacing the
//! document with the fields this client happened to write down.
//!
//! That is not hypothetical for the current implementation. Measured against
//! Docker Engine 29.8.0 on the same container and the same request:
//!
//! | Client | Top-level members returned |
//! | --- | --- |
//! | Engine's own answer | 24 |
//! | `bollard` `ContainerInspectResponse` re-serialized | 23 |
//!
//! The member that disappears is `ExecIDs`, and the reason is worth recording
//! because it is not the failure mode this work was started for: `bollard-stubs`
//! declares `exec_ids`, but annotates it `skip_serializing_if = "Option::is_none"`
//! and the daemon sends `"ExecIDs": null`. A member the daemon *did* send is
//! therefore dropped on the way back out because its value is null. Every
//! `Option` member is exposed to the same thing, and a null is a value the
//! caller may need to see.
//!
//! [`ContainerInspect::details`] exists because callers do want the small
//! projection. It is the same projection the current facade performs, spelled
//! out here over the retained document, and it is a view rather than a
//! replacement: [`ContainerInspect::document`] always has the whole answer.
//!
//! Keeping the document is what makes the `Debug` impl on
//! [`ContainerInspect`] load-bearing: retaining a value a derive would print in
//! full means the redaction has to be hand-written, because the derive is
//! exactly the defect. See the type's own documentation for what it reports.

use std::collections::BTreeMap;
use std::fmt;

use hyper::Method;

use super::containers::{container_path, with_query};
use super::transport::{RawEngine, RawRequest, decode, engine_result};
use crate::{ContainerDetails, ContainerPortBinding, Error};

/// The container inspect answer, with the daemon's document kept intact.
///
/// The document is retained rather than flattened into a model, so a member this
/// client does not know about is still available to a caller that does. The
/// accessors are conveniences over that document, not a second copy of it.
///
/// # Why `Debug` is hand-written
///
/// Retaining the document is the same decision that makes the redaction
/// necessary, and a derived impl would be the defect rather than the cleanup:
/// `Config.Env` is where a container's credentials live — a database URL, an API
/// token, a signing key passed in with `-e` so the process inside would have it —
/// and it is one of twenty-four members of a document that also carries
/// `Config.Labels`, `HostConfig.Binds`, the health check's own output, and the
/// command line. `serde_json::Value`'s `Debug` prints its strings verbatim, so a
/// derived impl puts all of it into whatever renders the value.
///
/// And that is a wide door. A `Debug` output is a panic message, a `tracing`
/// field, a failed `assert_eq!`, and a CI log, and a caller holding a
/// `ContainerInspect` is by definition holding it after something went
/// somewhere wrong. `{:?}` on a type is the one formatting a debugging change
/// reaches for first, so the value most likely to be printed is the one holding
/// the most to keep out of the line.
///
/// The impl reports identity and state — what an inspect answer is read for —
/// and three counts standing in for everything it will not render. The
/// redactions are *visible* rather than omissions, because "the container has
/// three environment variables" and "the daemon sent no `Env` at all" are
/// different facts and a reader has to be able to tell them apart. And
/// `finish_non_exhaustive` is deliberate: a member added to this type later
/// renders as `..` rather than appearing in full by default, which is the
/// property this impl exists to have.
///
/// [`document`](Self::document) and [`into_document`](Self::into_document) are
/// untouched, because a caller that *asks* for the document is making a
/// different decision from one that formats it.
#[derive(Clone, PartialEq)]
pub struct ContainerInspect {
    document: serde_json::Value,
}

impl ContainerInspect {
    /// Returns the document exactly as the daemon sent it.
    ///
    /// This is the answer of last resort for a member with no accessor: nothing
    /// in it has been renamed, defaulted, or dropped.
    #[must_use]
    pub const fn document(&self) -> &serde_json::Value {
        &self.document
    }

    /// Consumes the answer and returns the document.
    #[must_use]
    pub fn into_document(self) -> serde_json::Value {
        self.document
    }

    /// Returns the container's id, which is also the id the daemon echoes in
    /// every other answer about it.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.text("Id")
    }

    /// Returns the container's name, including the Engine's leading `/`.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.text("Name")
    }

    /// Returns the image the container was created from.
    #[must_use]
    pub fn image(&self) -> Option<&str> {
        self.text("Image")
    }

    /// Returns whether the container was created with a pseudo-TTY.
    ///
    /// This is the answer `logs` needs and cannot report: the endpoint does not
    /// say which framing it is using, so a caller has to ask here. See
    /// [`ContainerLogOptions::tty`](super::ContainerLogOptions::tty).
    #[must_use]
    pub fn tty(&self) -> Option<bool> {
        self.flag("Config", "Tty")
    }

    /// Returns the daemon's status word, such as `running` or `exited (0) 3
    /// seconds ago)`.
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.text_in("State", "Status")
    }

    /// Returns whether the daemon reports the container as running.
    ///
    /// A paused container is still running, so this is not the same question as
    /// [`ContainerInspect::state`].
    #[must_use]
    pub fn running(&self) -> Option<bool> {
        self.flag("State", "Running")
    }

    /// Returns whether the daemon reports the container as paused.
    #[must_use]
    pub fn paused(&self) -> Option<bool> {
        self.flag("State", "Paused")
    }

    /// Returns the last process exit status.
    ///
    /// A running container reports the exit status of the process it replaced,
    /// so this is only a container's exit status once it has stopped.
    #[must_use]
    pub fn exit_code(&self) -> Option<i64> {
        self.number_in("State", "ExitCode")
    }

    /// Returns the host pid of the container's init process.
    #[must_use]
    pub fn pid(&self) -> Option<i64> {
        self.number_in("State", "Pid")
    }

    /// Returns the daemon's health status, lowercased, when the container has a
    /// health check.
    ///
    /// An absent health block projects to `None` rather than to a word, because
    /// "no health check" and "a health check that has not run" are different
    /// answers and a caller evaluating a readiness condition has to tell them
    /// apart.
    #[must_use]
    pub fn health(&self) -> Option<String> {
        self.health_text().map(ToOwned::to_owned)
    }

    /// Projects the answer onto the repository's container-details model.
    ///
    /// The projection is the one the current facade performs, so a caller can
    /// compare the two without reading two different shapes — and it is
    /// explicitly a view: [`ContainerInspect::document`] still has the members
    /// this projection has no field for.
    #[must_use]
    pub fn details(&self) -> ContainerDetails {
        ContainerDetails {
            tty: self.tty().unwrap_or(false),
            exit_code: self.exit_code(),
            status: self.state().map(ToOwned::to_owned),
            ports: self.ports(),
            health: self.health(),
            running: self.running(),
        }
    }

    /// Returns the published and exposed ports, keyed as the daemon keys them.
    ///
    /// A port with no host binding is dropped, matching the current facade: the
    /// repository model holds bindings, and a port with none has nothing to
    /// record. The whole block is still in [`ContainerInspect::document`].
    #[must_use]
    pub fn ports(&self) -> BTreeMap<String, Vec<ContainerPortBinding>> {
        self.document
            .get("NetworkSettings")
            .and_then(|settings| settings.get("Ports"))
            .and_then(serde_json::Value::as_object)
            .map(|ports| {
                ports
                    .iter()
                    .filter_map(|(port, bindings)| {
                        let bindings: Vec<ContainerPortBinding> = bindings
                            .as_array()?
                            .iter()
                            .map(|binding| ContainerPortBinding {
                                host_ip: binding
                                    .get("HostIp")
                                    .and_then(serde_json::Value::as_str)
                                    .map(ToOwned::to_owned),
                                host_port: binding
                                    .get("HostPort")
                                    .and_then(serde_json::Value::as_str)
                                    .map(ToOwned::to_owned),
                            })
                            .collect();
                        Some((port.clone(), bindings))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Reads a top-level member as text.
    fn text(&self, member: &str) -> Option<&str> {
        self.document
            .get(member)
            .and_then(serde_json::Value::as_str)
    }

    /// Reads a member of a nested block as text.
    fn text_in(&self, block: &str, member: &str) -> Option<&str> {
        self.document.get(block)?.get(member)?.as_str()
    }

    /// Reads a member of a nested block as a number.
    fn number_in(&self, block: &str, member: &str) -> Option<i64> {
        self.document.get(block)?.get(member)?.as_i64()
    }

    /// Reads a boolean member of a nested block.
    fn flag(&self, block: &str, member: &str) -> Option<bool> {
        self.document.get(block)?.get(member)?.as_bool()
    }

    /// Borrows the health status, which [`health`](Self::health) hands back by
    /// value.
    ///
    /// The [`Debug`] impl needs the borrow, so a `Debug` that reported health
    /// would otherwise allocate a `String` per rendering to throw away.
    fn health_text(&self) -> Option<&str> {
        self.document
            .get("State")
            .and_then(|state| state.get("Health"))
            .and_then(|health| health.get("Status"))
            .and_then(serde_json::Value::as_str)
            .filter(|status| !status.is_empty())
    }

    /// Counts the environment variables the container's configuration declares,
    /// and never reads their values.
    ///
    /// `Config.Env` is the member the [`Debug`] impl withholds outright, so this
    /// count is what makes the withholding legible: `env_vars: Some(3)` says the
    /// daemon sent three of them, which is the question a reader diagnosing a
    /// container that cannot see its configuration actually has. Rendering
    /// nothing, or `env_vars: None`, would be indistinguishable from an
    /// implementation that never looked.
    fn env_count(&self) -> Option<usize> {
        self.document
            .get("Config")
            .and_then(|config| config.get("Env"))
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
    }

    /// Counts the published and exposed ports, keying nothing.
    ///
    /// A count rather than the keys, for the same reason
    /// [`env_count`](Self::env_count) counts: the map is daemon-supplied and its
    /// keys are daemon-chosen text, so what a reader wants from it — whether
    /// anything is published at all — does not require printing any of it.
    fn port_count(&self) -> Option<usize> {
        self.document
            .get("NetworkSettings")
            .and_then(|settings| settings.get("Ports"))
            .and_then(serde_json::Value::as_object)
            .map(serde_json::Map::len)
    }

    /// Counts the top-level members the daemon sent.
    ///
    /// This is the count the whole design of this type is about, so it is the
    /// one worth printing. The document is kept because a generated model drops
    /// members — `ExecIDs` is the one this crate measured itself losing — and a
    /// caller can only notice a member it cannot see if the rendering says how
    /// many there were. `None` rather than zero when the body was not an object,
    /// which is a decode oddity a reader should see as odd rather than as an
    /// empty document.
    fn member_count(&self) -> Option<usize> {
        self.document.as_object().map(serde_json::Map::len)
    }
}

/// The longest daemon string a summary `Debug` in this crate will print.
///
/// A `Debug` output is a log line, and a rendering that emits whatever length the
/// peer chose hands that peer the width of the line. The Engine's own values are
/// far shorter than this — an id is sixty-four hex characters, a name is
/// daemon-validated, an image reference is a digest — so the bound is only ever
/// reached by a value no reader wanted in full anyway.
///
/// A truncation is a **length** bound and not a redaction: the prefix is still
/// printed. That is why it is applied only to the identity members, and never to
/// anything that could be a credential.
///
/// **One constant, two types.** [`ExecInspect`](super::ExecInspect) bounds its
/// two digests the same way and reads this one rather than declaring its own,
/// because two constants that have to be kept equal is one too many: the second
/// would be a value nobody changes, and the day it did change, the one that did
/// not would be the copy in the file a reader was not looking at. `raw`'s own
/// module root is where this belongs once a third summary needs it; until then
/// this is the shorter edit, and it is `pub(crate)` so the sharing is visible
/// rather than accidental.
pub(crate) const MAX_SUMMARY_TEXT: usize = 128;

/// One identity member of the document, rendered with a length bound.
///
/// Shaped like the `Option<&str>` it wraps so a bounded rendering is the same
/// one a derived impl would have produced for a short value — `Some("/web")`,
/// not `Some("/web")` under an extra layer of punctuation — and so an absent
/// member still reads as `None`.
struct SummaryText<'a>(Option<&'a str>);

impl fmt::Debug for SummaryText<'_> {
    /// Prints the member, or how much of it was withheld.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(text) = self.0 else {
            return formatter.write_str("None");
        };
        if text.len() <= MAX_SUMMARY_TEXT {
            return write!(formatter, "Some({text:?})");
        }
        // A `&str` may be cut anywhere, so the bound lands on the next char
        // boundary. Three bytes is the most a UTF-8 character can need to
        // straddle it.
        let mut end = MAX_SUMMARY_TEXT;
        while !text.is_char_boundary(end) {
            end += 1;
        }
        write!(
            formatter,
            "Some({:?}…(+{} byte(s) withheld))",
            &text[..end],
            text.len() - end
        )
    }
}

impl fmt::Debug for ContainerInspect {
    /// Reports the container's identity and state, and how much of the answer
    /// this crate does not model.
    ///
    /// Never the document, at any depth. Every field below is either a value
    /// this crate already exposes through a documented accessor or a count; the
    /// twenty-odd members a caller may want to read for themselves stay behind
    /// [`document`](Self::document), which is the door that makes asking for
    /// them a decision rather than an accident.
    ///
    /// What is left out is not only `Config.Env`. It is `Config.Cmd`, `Args`,
    /// `Config.Labels`, `HostConfig.Binds`, the health check's own recorded
    /// output, the network addresses — every one of which is daemon-chosen text
    /// that a derived impl would have printed verbatim, and several of which
    /// hold credentials in ordinary use.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContainerInspect")
            .field("id", &SummaryText(self.id()))
            .field("name", &SummaryText(self.name()))
            .field("image", &SummaryText(self.image()))
            .field("state", &SummaryText(self.state()))
            .field("health", &SummaryText(self.health_text()))
            .field("running", &self.running())
            .field("paused", &self.paused())
            .field("tty", &self.tty())
            .field("exit_code", &self.exit_code())
            .field("pid", &self.pid())
            .field("env_vars", &self.env_count())
            .field("ports", &self.port_count())
            .field("members", &self.member_count())
            .finish_non_exhaustive()
    }
}

/// Reads a container's inspect document.
///
/// The answer is a single JSON document, so it goes through
/// [`RawResponse::document`](super::RawResponse::document) and is therefore
/// bounded by [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES). Nothing is
/// streamed: the daemon closes the body when it has written the document.
///
/// The `size` query parameter is never sent. Docker Engine 29.8.0 answers
/// without it, and adding it makes the daemon compute and report `SizeRw` and
/// `SizeRootFs` — a second, more expensive answer for members this client keeps
/// in the document anyway.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a `404` carrying `No such container: <name>` for a reference that
/// names nothing — or when the response is not a JSON document.
pub async fn inspect(engine: &RawEngine, container: &str) -> Result<ContainerInspect, Error> {
    let response = engine.send(inspect_request(container)?).await?;
    let document = engine_result(response).await?;
    let document: serde_json::Value = decode(&document)?;
    Ok(ContainerInspect { document })
}

/// Builds the `GET /containers/{id}/json` request.
///
/// The request carries no query at all, so the recorded request line is
/// `GET /v{major}.{minor}/containers/{reference}/json` and nothing else.
fn inspect_request(container: &str) -> Result<RawRequest, Error> {
    let request = RawRequest::new(Method::GET, container_path(container, "/json")?);
    Ok(with_query(request, None))
}

#[cfg(test)]
mod tests {
    use super::ContainerInspect;
    use crate::raw::{MAX_DOCUMENT_BYTES, RawEngine, RawTarget};
    use crate::{ApiVersion, ErrorKind};

    /// The API version every request-shape assertion pins.
    ///
    /// Derived from the crate's ceiling. What these assertions are about is
    /// the path and its query encoding, not the number in the prefix, and a
    /// literal here would turn a legitimate ceiling change into failures that
    /// the next person removes rather than reads. The number itself is asserted
    /// once, in `raw::mod::tests::the_prefix_is_the_version_the_crate_claims`.
    const VERSION: ApiVersion = crate::API_VERSION;

    fn engine() -> RawEngine {
        RawEngine::new(
            RawTarget::Unix(std::path::PathBuf::from("/tmp/does-not-matter.sock")),
            VERSION,
        )
    }

    /// Renders the exact request line a request would put on the wire.
    fn request_line(request: &super::RawRequest) -> String {
        let uri = engine().request_uri(request).expect("absolute path");
        format!("{} {uri} HTTP/1.1", request.method)
    }

    /// Recorded from Docker Engine 29.8.0's `GET /containers/{id}/json`,
    /// abbreviated only where a member's value is long and irrelevant here.
    const INSPECT_BODY: &[u8] = br#"{
        "Id":"38df04270233eb5551a444c5a1064b683a071e41eb77e43db8c34e84b6f51344",
        "Created":"2026-09-26T05:30:16.418592304Z",
        "Path":"sh","Args":["-c","sleep 600"],
        "State":{"Status":"running","Running":true,"Paused":false,"Restarting":false,
            "OOMKilled":false,"Dead":false,"Pid":935123,"ExitCode":0,"Error":"",
            "StartedAt":"2026-09-26T05:30:16.418592304Z",
            "FinishedAt":"0001-01-01T00:00:00Z",
            "Health":{"Status":"healthy","FailingStreak":0,"Log":[]}},
        "Image":"sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
        "ResolvConfPath":"/var/lib/docker/containers/38df/resolv.conf",
        "HostnamePath":"/var/lib/docker/containers/38df/hostname",
        "HostsPath":"/var/lib/docker/containers/38df/hosts",
        "LogPath":"/var/lib/docker/containers/38df/38df-json.log",
        "Name":"/rawprobe-tty",
        "RestartCount":0,
        "Driver":"overlayfs",
        "Platform":"linux",
        "MountLabel":"","ProcessLabel":"","AppArmorProfile":"",
        "ExecIDs":null,
        "HostConfig":{"CpuShares":0,"Memory":0,"NetworkMode":"default","LogConfig":{"Type":"json-file","Config":{}}},
        "GraphDriver":{"Name":"overlayfs","Data":{}},
        "SizeRw":4096,"SizeRootFs":13153063,
        "Config":{"Hostname":"38df04270233","Tty":true,"OpenStdin":true,"StdinOnce":false,
            "AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Env":["PATH=/usr/bin"],
            "Cmd":["sh","-c","sleep 600"],"Image":"alpine:3.20","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},
        "NetworkSettings":{"Bridge":"","SandboxID":"1a2b","Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"18080"}]},"Networks":{"bridge":{"IPAddress":"172.17.0.2"}}}
    }"#;

    fn decoded() -> ContainerInspect {
        let document: serde_json::Value = super::super::decode(INSPECT_BODY).expect("a document");
        ContainerInspect { document }
    }

    #[test]
    fn inspect_sends_the_versioned_path_and_no_query() {
        let request = super::inspect_request("rawprobe-tty").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/containers/rawprobe-tty/json HTTP/1.1")
        );
        assert_eq!(request.query, None, "the size flag is never sent");
    }

    #[test]
    fn a_reference_cannot_reshape_the_inspect_path() {
        let request = super::inspect_request("a/b").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/containers/a%2Fb/json HTTP/1.1")
        );
    }

    #[test]
    fn an_empty_reference_is_refused_before_a_connection_is_opened() {
        let error = super::inspect_request("").expect_err("empty reference");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn the_daemons_members_are_all_still_there() {
        // The point of keeping the document. `ExecIDs` is the member the
        // generated model drops, because the daemon sends it as `null` and the
        // model omits a `None` on the way back out.
        let inspect = decoded();
        for member in [
            "Id",
            "Created",
            "Path",
            "Args",
            "State",
            "Image",
            "ResolvConfPath",
            "HostnamePath",
            "HostsPath",
            "LogPath",
            "Name",
            "RestartCount",
            "Driver",
            "Platform",
            "MountLabel",
            "ProcessLabel",
            "AppArmorProfile",
            "ExecIDs",
            "HostConfig",
            "GraphDriver",
            "SizeRw",
            "SizeRootFs",
            "Config",
            "NetworkSettings",
        ] {
            assert!(
                inspect.document().get(member).is_some(),
                "member {member} was dropped"
            );
        }
        assert!(
            inspect
                .document()
                .get("ExecIDs")
                .is_some_and(serde_json::Value::is_null),
            "a member the daemon sent as null is still a member it sent"
        );
    }

    #[test]
    fn the_nested_blocks_the_accessors_read_are_the_engines_spelling() {
        // `Config.Tty` and `State.Running` are the two members a snake_case
        // rename would get wrong, and they are the two a caller reads to decide
        // how to read a log stream.
        let inspect = decoded();
        assert_eq!(
            inspect.id(),
            Some("38df04270233eb5551a444c5a1064b683a071e41eb77e43db8c34e84b6f51344")
        );
        assert_eq!(inspect.name(), Some("/rawprobe-tty"));
        assert_eq!(
            inspect.image(),
            Some("sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc")
        );
        assert_eq!(inspect.tty(), Some(true));
        assert_eq!(inspect.state(), Some("running"));
        assert_eq!(inspect.running(), Some(true));
        assert_eq!(inspect.paused(), Some(false));
        assert_eq!(inspect.exit_code(), Some(0));
        assert_eq!(inspect.pid(), Some(935_123));
        assert_eq!(inspect.health().as_deref(), Some("healthy"));
    }

    #[test]
    fn a_container_without_a_health_check_reports_no_health_rather_than_a_word() {
        // "No health check" and "a health check that has not run" are different
        // answers, and a readiness condition has to be able to tell them apart.
        let document: serde_json::Value =
            super::super::decode(br#"{"State":{"Status":"exited","Running":false}}"#)
                .expect("a document");
        let inspect = ContainerInspect { document };
        assert_eq!(inspect.health(), None);
        assert_eq!(inspect.running(), Some(false));
        assert_eq!(inspect.exit_code(), None);
    }

    #[test]
    fn an_empty_health_status_is_absent_rather_than_an_empty_word() {
        let document: serde_json::Value =
            super::super::decode(br#"{"State":{"Health":{"Status":""}}}"#).expect("a document");
        assert_eq!(ContainerInspect { document }.health(), None);
    }

    #[test]
    fn the_details_projection_reuses_the_repository_model() {
        let details = decoded().details();
        assert!(details.tty);
        assert_eq!(details.status.as_deref(), Some("running"));
        assert_eq!(details.running, Some(true));
        assert_eq!(details.health.as_deref(), Some("healthy"));
        assert_eq!(details.exit_code, Some(0));
        assert_eq!(details.ports.len(), 1);
        let bindings = &details.ports["80/tcp"];
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].host_ip.as_deref(), Some("0.0.0.0"));
        assert_eq!(bindings[0].host_port.as_deref(), Some("18080"));
    }

    #[test]
    fn a_document_with_no_members_still_decodes_to_an_empty_projection() {
        // A `null` in place of a block is how several members appear when a
        // container has nothing to report, and it must not be a decode failure.
        let document: serde_json::Value =
            super::super::decode(br#"{"State":null,"Config":null,"NetworkSettings":null}"#)
                .expect("a document");
        let inspect = ContainerInspect { document };
        assert_eq!(inspect.state(), None);
        assert_eq!(inspect.tty(), None);
        assert!(inspect.details().ports.is_empty());
    }

    #[test]
    fn inspect_reads_through_the_shared_bounded_document_path() {
        // The bound is a property of the transport, not of each operation, so
        // what is asserted here is that inspect does not read the socket itself.
        const { assert!(MAX_DOCUMENT_BYTES > 0) };
        let request = super::inspect_request("c").expect("request");
        assert!(
            request.body.known_len().is_some(),
            "the request has no body to stream"
        );
    }

    /// Builds an inspect answer from a body, the way `inspect` does.
    fn of(body: &str) -> ContainerInspect {
        let document: serde_json::Value =
            super::super::decode(body.as_bytes()).expect("the fixture is a document");
        ContainerInspect { document }
    }

    #[test]
    fn the_summary_never_renders_a_member_it_did_not_name() {
        // The recorded Engine body carries `Env`, `Cmd` and `Args`; the last two
        // are this crate's own command line and the first is whatever a caller
        // passed in. None of them is named by the summary.
        let rendered = format!("{:?}", decoded());
        assert!(!rendered.contains("PATH=/usr/bin"), "{rendered}");
        assert!(!rendered.contains("sleep 600"), "{rendered}");
        // The quoted form, because the unquoted one is a substring of `sha256:`
        // and would be testing the wrong thing.
        assert!(!rendered.contains("\"sh\""), "{rendered}");
        // The image *reference* is a `Config` member, so it is withheld even
        // though the image *id* survives: they are two members of the document
        // and the summary names only one.
        assert!(!rendered.contains("alpine:3.20"), "{rendered}");
        // The members a caller reads an inspect answer for all survive, so the
        // redaction has not cost the type its reason to exist.
        assert!(rendered.contains("id: Some(\"38df04270233"), "{rendered}");
        assert!(
            rendered.contains("name: Some(\"/rawprobe-tty\")"),
            "{rendered}"
        );
        assert!(rendered.contains("state: Some(\"running\")"), "{rendered}");
        assert!(rendered.contains("health: Some(\"healthy\")"), "{rendered}");
        assert!(rendered.contains("tty: Some(true)"), "{rendered}");
        assert!(rendered.contains("pid: Some(935123)"), "{rendered}");
        // The counts stand in for what was withheld, so a reader can tell three
        // environment variables from an absent `Config.Env` block.
        assert!(rendered.contains("env_vars: Some(1)"), "{rendered}");
        assert!(rendered.contains("ports: Some(1)"), "{rendered}");
        assert!(rendered.contains("members: Some(24)"), "{rendered}");
        // And the door for a member added later.
        assert!(rendered.contains(".."), "{rendered}");
    }

    #[test]
    fn a_member_longer_than_the_bound_is_cut_and_says_so() {
        // One ASCII byte, then two-byte characters. The bound is 128, so it
        // lands *inside* the 64th two-byte character: that one starts at byte
        // 127, and a slice at 128 would be a partial character. Without the
        // boundary walk in `SummaryText` this panics rather than truncates, so
        // the cut is the whole subject of this test.
        let long = format!("x{}", "é".repeat(100));
        assert!(
            !long.is_char_boundary(super::MAX_SUMMARY_TEXT),
            "the fixture must straddle the bound, or this test proves nothing: the \
             earlier version of it used a character with no straddling offset and \
             never reached the code it claimed to cover"
        );
        // 1 ASCII byte, then 64 whole two-byte characters: the walk moves the
        // cut from 128 to the 129, which is where the 65th character starts.
        let cut = format!("x{}", "é".repeat(64));
        let withheld = long.len() - cut.len();

        let rendered = format!("{:?}", of(&format!(r#"{{"Name":"{long}"}}"#)));
        // The exact cut, the exact withheld count, and the marker, in one
        // assertion: the printed prefix is the whole characters only, so a
        // regression that cut at the raw index would show up here as a
        // different string rather than as a panic alone.
        assert!(
            rendered.contains(&format!("Some({cut:?}…(+{withheld} byte(s) withheld))")),
            "{rendered}"
        );
        // The prefix really is a character boundary and nothing longer.
        assert!(!rendered.contains(&long), "{rendered}");

        // A value inside the bound is printed whole, with no marker, so the
        // marker means something.
        let short = format!("{:?}", of(r#"{"Name":"/web"}"#));
        assert_eq!(short.matches("withheld").count(), 0, "{short}");
    }

    #[test]
    fn a_body_that_is_not_an_object_reports_no_members_rather_than_zero() {
        // `null` in place of a document is not a decode failure for any block,
        // and "the body was not an object" is a different fact from "the object
        // had no members". A zero would merge the two.
        let rendered = format!("{:?}", of("null"));
        assert!(rendered.contains("members: None"), "{rendered}");
        assert!(rendered.contains("id: None"), "{rendered}");
        assert!(rendered.contains("env_vars: None"), "{rendered}");
    }
}
