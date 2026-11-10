# Bake planning fixtures

These JSON fixtures are intentionally small and deterministic. They exercise
only the RD-006 normalized document boundary:

- `defaults.json` — implicit context/Dockerfile defaults, variables, tags,
  platforms, stage, and boolean options;
- `inheritance.json` — ordered multiple-base-style field replacement and map
  merging;
- `selection.json` — default/release group expansion and a named target
  dependency;
- `inheritance-cycle.json` — target inheritance cycle;
- `target-cycle.json` — named `target:` context cycle; and
- `group-cycle.json` — nested group cycle.

The opt-in `templates/` fixtures cover safe helpers followed by native Bake
variable interpolation and rejection of an unsupported network helper. The
Compose v1 dotenv fixtures are shared with the Compose adapter and cover
quoting, ordering, precedence, interpolation, Windows key rules, invalid
assignments, and cancellation. No fixture contains a builder endpoint, solve
request, process/environment value, or nondeterministic generated data.
