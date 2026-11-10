# neotales-args

Literal argv parsing and argument ergonomics for Rust tools. It exists so callers
can parse portable command text without introducing shell evaluation.

```rust
use neotales_args::Args;

let args = Args::parse("tool 'two words' --flag")?;
assert_eq!(args.as_slice(), ["tool", "two words", "--flag"]);
# Ok::<(), neotales_args::Error>(())
```

## License

MIT. See the workspace `LICENSE.md`.
