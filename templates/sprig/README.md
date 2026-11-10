# neotales-sprig

Deterministic, side-effect-free Sprig-compatible helpers for template engines.
It exists to provide useful string/default helpers without environment, network,
filesystem, randomness, or process access.

```rust
let value = neotales_sprig::call("upper", &[neotales_sprig::Value::String("acme".to_owned())])?;
assert_eq!(value.render(), "ACME");
# Ok::<(), neotales_sprig::Error>(())
```

The safe V1 `default` helper has fixed arity two: it takes a fallback and a
value, treats `false`, empty strings, empty lists, and empty maps as empty, and
returns the selected typed `Value` unchanged. It does not implement the
variadic upstream form. Missing template paths remain errors in
`neotales-gotmpl`; the helper never substitutes a null value for a missing path.

## License

MIT. See the workspace `LICENSE.md`.
