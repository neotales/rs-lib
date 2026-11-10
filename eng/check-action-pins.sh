#!/usr/bin/env bash
# Fail unless every third-party action is pinned to a full commit SHA.
# A local action (./...) has no SHA. A tag or a branch is not a pin.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: eng/check-action-pins.sh <workflow-or-action>..." >&2
  exit 2
fi

fail=0
for file in "$@"; do
  while IFS= read -r line; do
    if [[ "$line" =~ uses:[[:space:]]*([^[:space:]#]+) ]]; then
      ref="${BASH_REMATCH[1]}"
      if [[ "$ref" == ./* ]]; then
        continue
      fi
      if [[ ! "$ref" =~ @[0-9a-f]{40}$ ]]; then
        echo "unpinned action in ${file}: ${line}"
        fail=1
      fi
    fi
  done < "$file"
done

exit "$fail"
