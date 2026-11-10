# neotales-process

Portable command graph parsing and direct process execution without invoking a
shell. It exists so applications can safely reuse literal argv pipelines and
`&&`, `||`, and `;` chains while keeping their own policy, environment planning,
and cancellation decisions.

```rust
use std::{collections::BTreeMap, path::Path};

let chain = neotales_process::parse("printf hello | grep hello")?;
let environment = BTreeMap::from([("PATH".into(), std::env::var("PATH").unwrap())]);
let cancelled = || false;
let options = neotales_process::ExecutionOptions {
    working_directory: Path::new("."),
    environment: &environment,
    passthrough: &[],
    is_cancelled: &cancelled,
    timeout: None,
};
let status = neotales_process::execute_chain(&chain, &options)?;
assert!(status.success());
# Ok::<(), neotales_process::Error>(())
```

The crate never constructs shell commands or mutates the global process
environment.

## License

MIT. See the workspace [LICENSE](../../LICENSE.md).
