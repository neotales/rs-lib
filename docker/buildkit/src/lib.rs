#![warn(missing_docs)]
#![allow(clippy::doc_markdown)]
//! Repository-owned BuildKit builder, solve, status, and cancellation contracts.
//!
//! This first slice is deliberately transport-free. It provides a fixture-backed
//! adapter so the public boundary can be tested before optional Bollard
//! BuildKit support is enabled. It does not select a builder from the process
//! environment, Docker configuration, or Buildx state.
#![doc = include_str!("../README.md")]

mod contract;
mod endpoint;
mod fixture;
mod input;

pub use contract::{
    AdapterCapabilities, AdapterError, BuildKitAdapter, CancellationRequest, SolveCancellation,
    SolveHandle, SolveId, SolveIdError, SolveStatus, StartSolveFuture, UnsupportedFeature,
};
pub use endpoint::{BuilderEndpoint, BuilderError, BuilderSelection};
pub use fixture::{BuildKitAdapterFixture, FIXTURE_FORMAT_VERSION, MAX_FIXTURE_BYTES};
pub use input::{
    BuildContext, BuildContextError, DockerfilePath, DockerfilePathError, MAX_BUILD_CONTEXT_BYTES,
    SolveRequest,
};
