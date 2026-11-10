# neotales-dotenv

`neotales-dotenv` parses dotenv documents without I/O, environment mutation, interpolation, or key-policy decisions. It retains source text, comments, blank lines, quote style, and recoverable invalid nodes so applications can report or edit configuration accurately.

## Usage

```rust
let document = neotales_dotenv::parse("export NAME='Neo Env'\n");
let assignment = document.assignments().next().unwrap();
assert_eq!(assignment.key, "NAME");
assert_eq!(assignment.value, "Neo Env");
```

## License

MIT. See the workspace [LICENSE](../../LICENSE.md).
