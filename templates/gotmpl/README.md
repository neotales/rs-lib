# neotales-gotmpl

A pure, safe Go `text/template` compatibility subset with deterministic Sprig
helpers. It exists for configuration and task rendering that must not inherit
shell behavior. Portable command parsing and execution live in `neotales-args`
and `neotales-process`, not in this template crate.

```rust
use std::collections::BTreeMap;
use neotales_gotmpl::Template;

let template = Template::parse("{{ .name | upper }}")?;
assert_eq!(template.render(&BTreeMap::from([("name".into(), "acme".into())]))?, "ACME");
# Ok::<(), neotales_gotmpl::Error>(())
```

## Bounded parsing and rendering

`Template::parse_with_options` accepts finite source and nesting limits.
`Template::render_typed_with_options` accepts finite output, range-iteration,
function-call, named-template-expansion, evaluation, and nesting limits. Both
operations can observe a cooperative `Fn() -> bool` cancellation callback.
Resource-limit failures use `Error::ResourceLimitExceeded` and do not include
rendered values. A parsed template owns immutable definitions and can be
rendered concurrently with independent options.

```rust
use neotales_gotmpl::{RenderOptions, Template};

let template = Template::parse("{{ .name | upper }}")?;
let options = RenderOptions::default().with_max_output_length(64);
let output = template.render_with_options(
    &std::collections::BTreeMap::from([("name".into(), "acme".into())]),
    &options,
)?;
assert_eq!(output, "ACME");
# Ok::<(), neotales_gotmpl::Error>(())
```

## License

MIT. See the workspace `LICENSE.md`.
