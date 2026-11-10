# neotales-env

Pure environment interpolation, PATH composition, and reversible shell diffs.
It exists to keep environment planning deterministic and separate from process
environment mutation.

```rust
let home = neotales_env::interpolate_with("$HOME/bin", |key| {
    (key == "HOME").then_some("/home/dev")
});
let braced = neotales_env::interpolate_with("${HOME}/bin", |key| {
    (key == "HOME").then_some("/home/dev")
});
assert_eq!(home, "/home/dev/bin");
assert_eq!(braced, "/home/dev/bin");
```

## License

MIT. See the workspace `LICENSE.md`.
