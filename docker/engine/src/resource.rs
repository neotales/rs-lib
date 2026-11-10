//! Shared helpers for repository-owned Engine resource boundaries.

use std::collections::BTreeMap;

use bollard::Docker;

/// Encodes Docker's JSON filter representation in stable key order.
pub(crate) fn encode_filters(filters: &BTreeMap<String, Vec<String>>) -> String {
    let json = serde_json::to_string(filters).expect("resource filters must serialize");
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("filters", &json);
    serializer.finish()
}

/// Adds a pre-encoded query parameter to a generated Bollard request.
///
/// Bollard 0.21.1 stores filter maps in `HashMap`s, which makes their JSON
/// query value nondeterministic. Resource facades use this modifier after
/// Bollard has built the request so the public ordered map remains stable.
pub(crate) fn with_filter_query(
    docker: &Docker,
    path: &'static str,
    filters: Option<&BTreeMap<String, Vec<String>>>,
) -> Docker {
    let Some(filters) = filters.filter(|filters| !filters.is_empty()) else {
        return docker.clone();
    };
    let encoded = encode_filters(filters);
    with_query_parameter(docker, path, encoded)
}

/// Adds the query a `GET /services` list request needs: `status=true`, plus the
/// caller's filters when there are any.
///
/// `status=true` is not optional. Without it the daemon answers with **every**
/// service's `ServiceStatus` member set to `null`, so a caller asking for
/// running and desired task counts gets nothing. Measured against Docker 29.8.0
/// on the same daemon, the same request with and without the parameter:
///
/// | request | `ServiceStatus` |
/// | --- | --- |
/// | `GET /v1.53/services` | `null` for every service |
/// | `GET /v1.53/services?status=true` | `{"RunningTasks":0,"DesiredTasks":1,"CompletedTasks":0}` |
///
/// It is not a detail of presentation. `docker service ls` prints `REPLICAS` as
/// `running/desired`, so without this parameter that column is empty for every
/// service — and the value is not derivable from the spec: the `0/1` of a
/// service whose image cannot be pulled is only knowable from the task counts.
/// A logging proxy confirms the CLI issues `GET /v1.56/services?status=true`.
///
/// # Why this is one modifier and not two
///
/// **Bollard 0.21.1's `with_request_modifier` replaces rather than chains**:
/// `docker.rs:1343` is `self.request_modifier = Some(Arc::new(modifier))`. Two
/// calls therefore do not compose — the second discards the first. Adding
/// `status=true` by calling [`with_query_parameter`] after
/// [`with_filter_query`] silently drops the caller's filters, and a request that
/// was scoped to one stack becomes one that asks for *every* service on the
/// daemon. That failure has no error and no diagnostic; the request simply
/// returns too much.
///
/// So the whole query is built here and applied in a single modifier. If another
/// Engine option is ever needed on a list request, add it to this function
/// rather than chaining a second call.
pub(crate) fn with_service_list_query(
    docker: &Docker,
    filters: Option<&BTreeMap<String, Vec<String>>>,
) -> Docker {
    let mut query = Vec::new();
    if let Some(filters) = filters.filter(|filters| !filters.is_empty()) {
        // `encode_filters` already emits the whole `filters=<json>` pair, key
        // included. Prefixing it again produced `filters=filters%3D…`, which the
        // daemon reads as a filter whose *name* is the string `filters=…`.
        query.push(encode_filters(filters));
    }
    query.push("status=true".to_owned());
    with_query_parameter(docker, "/services", query.join("&"))
}

/// Adds one already-encoded query parameter to a generated Bollard request.
///
/// This is used for Engine options that Bollard 0.21.1 does not expose through
/// its generated request type. The encoded value must be produced with a
/// form serializer so nested JSON and reserved characters remain unambiguous.
pub(crate) fn with_query_parameter(
    docker: &Docker,
    path: &'static str,
    encoded_parameter: String,
) -> Docker {
    docker.clone().with_request_modifier(move |mut request| {
        if request.uri().path().ends_with(path) {
            add_query_parameter(&mut request, &encoded_parameter);
        }
        request
    })
}

fn add_query_parameter(request: &mut bollard::BollardRequest, encoded_parameter: &str) {
    let existing = request.uri().query().unwrap_or_default();
    let query = if existing.is_empty() {
        encoded_parameter.to_owned()
    } else {
        format!("{existing}&{encoded_parameter}")
    };
    let path_and_query = format!("{}?{}", request.uri().path(), query);
    if let Ok(path_and_query) = path_and_query.parse::<http::uri::PathAndQuery>() {
        let mut parts = request.uri().clone().into_parts();
        parts.path_and_query = Some(path_and_query);
        if let Ok(uri) = http::Uri::from_parts(parts) {
            *request.uri_mut() = uri;
        }
    }
}
