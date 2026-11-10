//! Dictionary helpers: building, reading, deriving, and combining keyed values.
//!
//! A dictionary is the only way a template carries a name/value structure, so
//! these helpers are the whole vocabulary for one: `dict` builds it, `get`,
//! `hasKey`, `keys`, `values`, `pluck`, and `dig` read it, `set`, `unset`,
//! `pick`, and `omit` derive a new one, and `merge`, `mergeOverwrite`,
//! `deepCopy`, and `deepEqual` combine and compare them.
//!
//! Two behaviors are worth stating up front because neither is obvious from the
//! name. The destination of `merge` is its *first* argument and wins over the
//! sources, which is the opposite of the order the name suggests. And the
//! list-returning helpers hand their keys back in ordinal order rather than in
//! the order a caller wrote them, so a rendered template does not depend on the
//! iteration order of the map it came from.

use std::collections::{BTreeMap, BTreeSet};

use crate::support;
use crate::{Context, Error, Value, arity, invalid};

/// Dispatches a dictionary helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

// No dictionary helper reads the call site; only `env` and `expandenv` do.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    _context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    let result = match name {
        "dict" => dict(arguments),
        "get" => get(arguments),
        "set" => set(arguments),
        "unset" => unset(arguments),
        "hasKey" => has_key(arguments),
        "pluck" => pluck(arguments),
        "keys" => keys(arguments),
        "values" => values(arguments),
        "pick" => pick(arguments),
        "omit" => omit(arguments),
        "dig" => dig(arguments),
        "merge" => merge(name, arguments, false),
        "mergeOverwrite" => merge(name, arguments, true),
        "deepCopy" => deep_copy(arguments),
        "deepEqual" => deep_equal(arguments),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
pub(super) fn takes_rendered_strings(_name: &str) -> bool {
    // A dictionary helper that saw `"map[a:1]"` could not walk the structure, so
    // every helper here needs the typed value.
    false
}

/// Builds a map from alternating keys and values.
///
/// `Dict` takes any number of arguments, including none. An odd trailing key is
/// stored against an empty string rather than refused, which is what makes
/// `dict 1 2 "three" "four" 5 | get "5"` an empty string instead of an error,
/// and a repeated key keeps its last value.
fn dict(arguments: &[Value]) -> Result<Value, Error> {
    arity("dict", arguments.len(), 0, None)?;
    let mut entries = BTreeMap::new();
    // `Dict` steps through the arguments two at a time, so only the even indexes
    // are keys and the odd ones are their values.
    for pair in arguments.chunks(2) {
        let value = pair
            .get(1)
            .cloned()
            .unwrap_or_else(|| Value::String(String::new()));
        entries.insert(pair[0].render(), value);
    }
    Ok(Value::Map(entries))
}

/// Returns the value at `KEY`, or an empty string when the key is absent.
///
/// `Get` answers a missing key with `""` rather than an error, because a
/// template reading an optional value should not have to guard the lookup.
fn get(arguments: &[Value]) -> Result<Value, Error> {
    arity("get", arguments.len(), 2, Some(2))?;
    let (entries, key) = map_key("get", arguments)?;
    Ok(entries
        .get(&key)
        .cloned()
        .unwrap_or_else(|| Value::String(String::new())))
}

/// Returns a copy of the map with `KEY` set to `VALUE`.
///
/// The reference's `Set` writes through to the map it was handed, which its
/// engine can observe because a template variable and the value it holds are the
/// same object. `Value` is a persistent tree instead, so the new map is
/// returned: the rendered result of `set` is the same either way, and a caller
/// that ignores it cannot accidentally change a dictionary another helper reads.
fn set(arguments: &[Value]) -> Result<Value, Error> {
    arity("set", arguments.len(), 3, Some(3))?;
    let mut updated = support::map("set", &arguments[0])?.clone();
    updated.insert(arguments[1].render(), arguments[2].clone());
    Ok(Value::Map(updated))
}

/// Returns a copy of the map with every named key removed.
///
/// `Unset` in the reference takes exactly one key. Upstream Sprig's `unset`
/// removes every key it is given, and that is the behavior kept here: a caller
/// naming two keys is asking for both to go, and a key that is already absent is
/// not an error.
fn unset(arguments: &[Value]) -> Result<Value, Error> {
    arity("unset", arguments.len(), 2, None)?;
    let mut remaining = support::map("unset", &arguments[0])?.clone();
    for key in &arguments[1..] {
        remaining.remove(&key.render());
    }
    Ok(Value::Map(remaining))
}

/// Reports whether the map holds `KEY`.
fn has_key(arguments: &[Value]) -> Result<Value, Error> {
    arity("hasKey", arguments.len(), 2, Some(2))?;
    let (entries, key) = map_key("hasKey", arguments)?;
    Ok(Value::Bool(entries.contains_key(&key)))
}

/// Collects one key from every map in a list of maps.
///
/// `Pluck` requires every source to be a map, and then drops the ones that do
/// not carry the key. So `pluck "name" $a $b` returns one value per map that has
/// a name, and a map without one shortens the result instead of filling it with
/// an empty string.
fn pluck(arguments: &[Value]) -> Result<Value, Error> {
    arity("pluck", arguments.len(), 2, None)?;
    let key = arguments[0].render();
    let mut plucked = Vec::new();
    for source in &arguments[1..] {
        let entries = support::map("pluck", source)?;
        if let Some(value) = entries.get(&key) {
            plucked.push(value.clone());
        }
    }
    Ok(Value::List(plucked))
}

/// Returns the keys of every map, in ordinal order.
///
/// `Keys` takes more than one map and sorts the flattened result, so the order
/// is the same whichever order the maps were passed in. It does not deduplicate,
/// so a key held by two of the maps is listed twice.
fn keys(arguments: &[Value]) -> Result<Value, Error> {
    arity("keys", arguments.len(), 1, None)?;
    let mut names = Vec::new();
    for source in arguments {
        names.extend(support::map("keys", source)?.keys().cloned());
    }
    names.sort_unstable();
    Ok(Value::List(names.into_iter().map(Value::String).collect()))
}

/// Returns a map's values, in key order.
///
/// `Values` takes exactly one map and orders its values by key, which is the
/// order a `BTreeMap` already iterates in, so `keys` and `values` line up.
fn values(arguments: &[Value]) -> Result<Value, Error> {
    arity("values", arguments.len(), 1, Some(1))?;
    let entries = support::map("values", &arguments[0])?;
    Ok(Value::List(entries.values().cloned().collect()))
}

/// Returns a map holding only the named keys.
fn pick(arguments: &[Value]) -> Result<Value, Error> {
    select("pick", arguments, true)
}

/// Returns a map without the named keys.
fn omit(arguments: &[Value]) -> Result<Value, Error> {
    select("omit", arguments, false)
}

/// Walks a path of keys into nested maps, answering `DEFAULT` when it misses.
///
/// `DEFAULT` is a required argument and is returned with its own type, so
/// `dig "a" "b" 0 $d` yields the number `0` rather than its text. The path
/// stops being followed at a value that is not a map: the last step may return
/// one, and an earlier step means the path could not be walked, so the default
/// is returned. A path that runs out on a map likewise falls back, which is why
/// `dig "a" "b" "c" "nope" $d` over `{"a": {"b": "c"}}` is `"nope"` and not
/// `"c"`.
fn dig(arguments: &[Value]) -> Result<Value, Error> {
    arity("dig", arguments.len(), 3, None)?;
    let depth = arguments.len() - 2;
    let mut entries = support::map("dig", &arguments[arguments.len() - 1])?;
    for (step, key) in arguments[..depth].iter().enumerate() {
        let Some(found) = entries.get(&key.render()) else {
            return Ok(arguments[depth].clone());
        };
        match found {
            Value::Map(nested) => entries = nested,
            _ if step + 1 == depth => return Ok(found.clone()),
            _ => return Ok(arguments[depth].clone()),
        }
    }
    Ok(arguments[depth].clone())
}

/// Merges every later argument into the first one, which is the destination.
///
/// `MergeMaps` reads the destination from `Arguments[0]`, so the map that wins
/// is the one written first, and `MergeInto` descends into two maps that share a
/// key. The merge is deep: `merge $dst $src` adds the keys of `$src` that `$dst`
/// lacks and leaves the ones it has alone, at every level of nesting.
fn merge(name: &str, arguments: &[Value], overwrite: bool) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, None)?;
    let mut destination = support::map(name, &arguments[0])?.clone();
    for source in &arguments[1..] {
        destination = merge_into(&destination, support::map(name, source)?, overwrite);
    }
    Ok(Value::Map(destination))
}

/// Returns a deep copy of the maps in `merge` and `mergeOverwrite`.
///
/// A key held by two maps is merged again rather than replaced, which is what
/// makes the merge deep. Otherwise the source fills in only what the destination
/// lacks, or overwrites it when `overwrite` is set, and neither argument is
/// modified.
fn merge_into(
    destination: &BTreeMap<String, Value>,
    source: &BTreeMap<String, Value>,
    overwrite: bool,
) -> BTreeMap<String, Value> {
    let mut merged = destination.clone();
    for (key, value) in source {
        if let (Some(Value::Map(existing)), Value::Map(incoming)) = (merged.get(key), value) {
            let nested = merge_into(existing, incoming, overwrite);
            merged.insert(key.clone(), Value::Map(nested));
            continue;
        }
        if overwrite || !merged.contains_key(key) {
            merged.insert(key.clone(), value.clone());
        }
    }
    merged
}

/// Returns a copy of a value that shares no structure with the original.
///
/// `Copy` recurses through lists and maps. `Value` is persistent, so the copy is
/// a fresh tree and the reference's aliasing hazard — where a copy that shares a
/// nested map can be written through to change the original — cannot arise.
fn deep_copy(arguments: &[Value]) -> Result<Value, Error> {
    arity("deepCopy", arguments.len(), 1, Some(1))?;
    Ok(copy_value(&arguments[0]))
}

/// Copies a value, rebuilding every list and map beneath it.
fn copy_value(value: &Value) -> Value {
    match value {
        Value::List(values) => Value::List(values.iter().map(copy_value).collect()),
        Value::Map(entries) => Value::Map(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), copy_value(value)))
                .collect(),
        ),
        scalar => scalar.clone(),
    }
}

/// Reports whether two values are structurally equal.
///
/// `DeepEqual` compares `Equal`, which checks the kind of both sides and then
/// their contents, recursing through lists and maps. That is exactly the
/// comparison the derived `PartialEq` on `Value` performs, including the part
/// that matters here: the string `"1"` is not the number `1`.
fn deep_equal(arguments: &[Value]) -> Result<Value, Error> {
    arity("deepEqual", arguments.len(), 2, Some(2))?;
    Ok(Value::Bool(arguments[0] == arguments[1]))
}

/// Reproduces the reference's `MapKey`, which `get` and `hasKey` share.
///
/// The map may be written on either side of the key, so `get $d "k"` and
/// `get "k" $d` are the same lookup. Nothing else about the two arguments is
/// interchangeable, so a call with no map at all is refused.
fn map_key<'a>(
    helper: &str,
    arguments: &'a [Value],
) -> Result<(&'a BTreeMap<String, Value>, String), Error> {
    if let Value::Map(entries) = &arguments[0] {
        return Ok((entries, arguments[1].render()));
    }
    if let Value::Map(entries) = &arguments[1] {
        return Ok((entries, arguments[0].render()));
    }
    Err(invalid(helper, "a dictionary argument"))
}

/// Reproduces the reference's `MapSelection`, which `pick` and `omit` share.
///
/// The map is whichever argument is a map, and every other argument is a key read
/// in its rendered form — which is what lets `pick $d 2` name the key `"2"`, and
/// lets a number and the string it renders as be the same key. Naming no key at
/// all is legal: `pick` then returns an empty map and `omit` returns the map
/// unchanged.
fn select(name: &str, arguments: &[Value], include: bool) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, None)?;
    let Some((index, entries)) = arguments.iter().enumerate().find_map(|(index, argument)| {
        support::map(name, argument)
            .ok()
            .map(|entries| (index, entries))
    }) else {
        return Err(invalid(name, "a dictionary argument"));
    };
    let wanted: BTreeSet<String> = arguments
        .iter()
        .enumerate()
        .filter(|(position, _)| *position != index)
        .map(|(_, argument)| argument.render())
        .collect();
    let selected = entries
        .iter()
        .filter(|(key, _)| wanted.contains(*key) == include)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Ok(Value::Map(selected))
}

#[cfg(test)]
mod tests {
    use super::{Context, Error, Value, dispatch};
    use std::collections::BTreeMap;

    /// Calls a dictionary helper, so a test cannot pass by accident on a name
    /// this module does not claim.
    fn helper(name: &str, arguments: &[Value]) -> Result<Value, Error> {
        match dispatch(name, arguments, &Context::default()) {
            Some(result) => result,
            None => panic!("{name} is not a dictionary helper"),
        }
    }

    /// Builds a map from alternating strings, for readable expectations.
    fn map(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    fn text(value: &str) -> Value {
        Value::String((*value).to_owned())
    }

    fn number(value: f64) -> Value {
        Value::Number(value)
    }

    #[test]
    fn claims_only_its_own_helpers() {
        assert!(dispatch("dict", &[], &Context::default()).is_some());
        assert!(dispatch("deepEqual", &[], &Context::default()).is_some());
        // `None` hands the name to the next module.
        assert!(dispatch("upper", &[text("a")], &Context::default()).is_none());
        assert!(!super::takes_rendered_strings("get"));
        assert!(!super::takes_rendered_strings("toStrings-not-mine"));
    }

    #[test]
    fn dict_pairs_keys_and_values() {
        // fixtures/sprig/upstream_parity.json[65]:
        // {{ $url := dict "fragment" "fragment" "host" "host:80" "path" "/path"
        //    "query" "query" "scheme" "proto" }} feeds the same five keys to
        // urlJoin, so the map is exactly these entries.
        let built = helper(
            "dict",
            &[
                text("fragment"),
                text("fragment"),
                text("host"),
                text("host:80"),
                text("path"),
                text("/path"),
                text("query"),
                text("query"),
                text("scheme"),
                text("proto"),
            ],
        )
        .expect("dict");
        assert_eq!(
            built.render(),
            "map[fragment:fragment host:host:80 path:/path query:query scheme:proto]"
        );
    }

    #[test]
    fn dict_keeps_keys_sorted_and_typed() {
        // `Dict` builds a `SortedDictionary`, so the rendered order is ordinal
        // and not the order the pairs were written in.
        assert_eq!(
            helper("dict", &[text("b"), number(2.0), text("a"), number(1.0)])
                .expect("dict")
                .render(),
            "map[a:1 b:2]"
        );
        assert_eq!(helper("dict", &[]).expect("dict"), map(&[]));
    }

    #[test]
    fn dict_gives_an_odd_trailing_key_an_empty_value() {
        // SprigUpstreamParityTests.DictionaryAllowsAnOddFinalKeyLikeUpstream:
        // {{ dict 1 2 "three" "four" 5 | get "5" }} renders the empty string.
        let built = helper(
            "dict",
            &[
                number(1.0),
                number(2.0),
                text("three"),
                text("four"),
                number(5.0),
            ],
        )
        .expect("dict");
        assert_eq!(helper("get", &[built, text("5")]).expect("get"), text(""));
        // The same test: a repeated key keeps its last value.
        let repeated = helper(
            "dict",
            &[text("key"), text("first"), text("key"), text("second")],
        )
        .expect("dict");
        assert_eq!(
            helper("get", &[repeated, text("key")]).expect("get"),
            text("second")
        );
    }

    #[test]
    fn get_reads_a_key_from_either_side() {
        // fixtures/sprig/upstream_parity.json[160]:
        // {{ $d := dict "key" "value" }}{{ get (mustDeepCopy $d) "key" }} => value
        let entries = map(&[("key", text("value"))]);
        assert_eq!(
            helper("get", &[entries.clone(), text("key")]).expect("get"),
            text("value")
        );
        // fixtures/sprig/upstream_parity.json[44]: {{ dict "name" "neo" | get "name" }}
        // renders `neo`.
        let named = helper("dict", &[text("name"), text("neo")]).expect("dict");
        assert_eq!(
            helper("get", &[named, text("name")]).expect("get"),
            text("neo")
        );
        // `MapKey` accepts the map in either position.
        assert_eq!(
            helper("get", &[text("key"), entries.clone()]).expect("get"),
            text("value")
        );
        // A number key is rendered, so `get $d 2` finds the string key "2".
        let numbered = map(&[("2", text("two"))]);
        assert_eq!(
            helper("get", &[numbered, number(2.0)]).expect("get"),
            text("two")
        );
    }

    #[test]
    fn get_answers_a_missing_key_with_an_empty_string() {
        // SprigUpstreamParityTests.CoreTemplateAndDictionaryBehaviorsMatchUpstreamContracts:
        // ... {{ get $d "missing" }} renders the empty string.
        let entries = map(&[("one", number(1.0)), ("two", number(2.0))]);
        assert_eq!(
            helper("get", &[entries, text("missing")]).expect("get"),
            text("")
        );
    }

    #[test]
    fn get_refuses_a_call_with_no_map() {
        let error = helper("get", &[text("a"), text("b")]).expect_err("no map");
        assert!(matches!(error, Error::InvalidArgument { .. }), "{error:?}");
        let arity = helper("get", &[text("a")]).expect_err("one argument");
        assert!(
            matches!(arity, Error::WrongArgumentCount { .. }),
            "{arity:?}"
        );
    }

    #[test]
    fn set_returns_a_new_map_and_leaves_the_original_alone() {
        // SprigUpstreamParityTests.SetAndUnsetMutateTheirUpstreamDictionaryArgument
        // writes `two` to 3; the value the helper returns carries that write, and
        // the argument it was given still reads 2 because `Value` is persistent.
        let original = map(&[("one", number(1.0)), ("two", number(2.0))]);
        let updated = helper("set", &[original.clone(), text("two"), number(3.0)]).expect("set");
        assert_eq!(updated, map(&[("one", number(1.0)), ("two", number(3.0))]));
        assert_eq!(original, map(&[("one", number(1.0)), ("two", number(2.0))]));
        assert_eq!(
            helper("set", &[original, text("three"), text("3")])
                .expect("set")
                .render(),
            "map[one:1 three:3 two:2]"
        );
    }

    #[test]
    fn unset_removes_every_named_key() {
        let original = map(&[
            ("name", text("neo")),
            ("nested", map(&[("value", text("found"))])),
            ("one", text("1")),
        ]);
        // SprigUpstreamParityTests.DictionaryFunctionsMatchTheSupportedUpstreamContracts
        // unsets "one" and then lists what is left as `name,nested,two`.
        let trimmed = helper("unset", &[original.clone(), text("one")]).expect("unset");
        assert_eq!(
            helper("keys", std::slice::from_ref(&trimmed))
                .expect("keys")
                .render(),
            "[name nested]"
        );
        // A second key goes too, and an absent key is not an error.
        let trimmed = helper("unset", &[trimmed, text("name"), text("absent")]).expect("unset");
        assert_eq!(
            trimmed,
            map(&[("nested", map(&[("value", text("found"))]))])
        );
    }

    #[test]
    fn has_key_reports_whether_a_key_is_present() {
        let entries = map(&[("one", number(1.0)), ("two", number(2.0))]);
        // The same reference test asserts `hasKey $dictionary "one"` is `false`
        // once "one" has been unset; a key the map never had reads the same way.
        assert_eq!(
            helper("hasKey", &[entries.clone(), text("two")]).expect("hasKey"),
            Value::Bool(true)
        );
        assert_eq!(
            helper("hasKey", &[entries.clone(), text("three")]).expect("hasKey"),
            Value::Bool(false)
        );
        assert_eq!(
            helper("hasKey", &[text("two"), entries]).expect("hasKey"),
            Value::Bool(true)
        );
    }

    #[test]
    fn pluck_collects_a_key_and_skips_maps_without_it() {
        // SprigUpstreamParityTests.DictionaryFunctionsMatchTheSupportedUpstreamContracts:
        // {{ pluck "name" .dictionary .other | join "," }} renders `neo,sprig`.
        let dictionary = map(&[
            ("name", text("neo")),
            ("nested", map(&[("value", text("found"))])),
        ]);
        let other = map(&[("name", text("sprig"))]);
        assert_eq!(
            helper("pluck", &[text("name"), dictionary.clone(), other.clone()])
                .expect("pluck")
                .render(),
            "[neo sprig]"
        );
        // `Pluck` requires every source to be a map, and a map without the key
        // shortens the result rather than contributing an empty string.
        let without_name = map(&[("other", text("value"))]);
        assert_eq!(
            helper("pluck", &[text("name"), dictionary, without_name, other])
                .expect("pluck")
                .render(),
            "[neo sprig]"
        );
        let error = helper("pluck", &[text("name"), text("not a map")]).expect_err("scalar source");
        assert!(matches!(error, Error::InvalidArgument { .. }), "{error:?}");
    }

    #[test]
    fn keys_sorts_across_every_map() {
        // The same reference test renders `name,nested,two` for a map that also
        // has "one": "one" is gone by then, and the rest are in ordinal order
        // rather than the order the dictionary was written in.
        let entries = map(&[
            ("two", text("2")),
            ("name", text("neo")),
            ("nested", map(&[])),
        ]);
        assert_eq!(
            helper("keys", std::slice::from_ref(&entries))
                .expect("keys")
                .render(),
            "[name nested two]"
        );
        // `Keys` accepts more than one map and sorts the flattened result.
        let first = map(&[("b", text("1"))]);
        let second = map(&[("a", text("2"))]);
        assert_eq!(
            helper("keys", &[first, second]).expect("keys").render(),
            "[a b]"
        );
        // It does not deduplicate, so a key in both maps is listed twice.
        let shared = map(&[("a", text("1"))]);
        assert_eq!(
            helper("keys", &[shared.clone(), shared])
                .expect("keys")
                .render(),
            "[a a]"
        );
    }

    #[test]
    fn values_are_returned_in_key_order() {
        // fixtures/sprig/upstream_parity.json[148]:
        // {{ $d := dict "a" 1 "b" 2 }}{{ values $d | sortAlpha | join "," }}
        // renders `1,2`; the values themselves are in that order already.
        let entries = map(&[("a", number(1.0)), ("b", number(2.0))]);
        assert_eq!(
            helper("values", &[entries]).expect("values"),
            Value::List(vec![number(1.0), number(2.0)])
        );
        assert!(matches!(
            helper("values", &[text("nope")]).expect_err("scalar"),
            Error::InvalidArgument { .. }
        ));
    }

    #[test]
    fn pick_keeps_the_named_keys() {
        // SprigUpstreamParityTests.CoreTemplateAndDictionaryBehaviorsMatchUpstreamContracts:
        // {{ $d := dict "one" 1 "two" 2 }}{{ pick $d "two" | len }} is 1.
        let entries = map(&[("one", number(1.0)), ("two", number(2.0))]);
        assert_eq!(
            helper("pick", &[entries.clone(), text("two")]).expect("pick"),
            map(&[("two", number(2.0))])
        );
        // `MapSelection` finds the map wherever it is written, and reads a key
        // argument in its rendered form, so a number names the string key "2".
        let numbered = map(&[("2", text("two"))]);
        assert_eq!(
            helper("pick", &[number(2.0), numbered]).expect("pick"),
            map(&[("2", text("two"))])
        );
        // DictionaryAllowsAnOddFinalKeyLikeUpstream: `pick $d` is empty.
        assert_eq!(helper("pick", &[entries]).expect("pick"), map(&[]));
    }

    #[test]
    fn omit_drops_the_named_keys() {
        // The same two tests: `{{ omit $d "one" | len }}` is 1 and `{{ omit $d | len }}` is 2.
        let entries = map(&[("one", number(1.0)), ("two", number(2.0))]);
        assert_eq!(
            helper("omit", &[entries.clone(), text("one")]).expect("omit"),
            map(&[("two", number(2.0))])
        );
        assert_eq!(
            helper("omit", &[entries]).expect("omit").render(),
            "map[one:1 two:2]"
        );
        let error = helper("omit", &[text("one"), text("two")]).expect_err("no map");
        assert!(matches!(error, Error::InvalidArgument { .. }), "{error:?}");
    }

    #[test]
    fn dig_walks_a_path_and_answers_the_default() {
        // SprigUpstreamParityTests.DictionaryFunctionsMatchTheSupportedUpstreamContracts:
        // {{ dig "nested" "value" "fallback" .dictionary }} renders `found`.
        let dictionary = map(&[
            ("one", text("1")),
            ("nested", map(&[("value", text("found"))])),
            ("name", text("neo")),
        ]);
        assert_eq!(
            helper(
                "dig",
                &[
                    text("nested"),
                    text("value"),
                    text("fallback"),
                    dictionary.clone()
                ]
            )
            .expect("dig"),
            text("found")
        );
        // RemainingUpstreamContractsMatch: over {"a": {"b": {"c": 1}}},
        // {{ dig "a" "b" "z" "fallback" $d }} renders `fallback`, because the
        // path continues past a value that is not a map.
        let nested = map(&[("a", map(&[("b", map(&[("c", number(1.0))]))]))]);
        assert_eq!(
            helper(
                "dig",
                &[text("a"), text("b"), text("z"), text("fallback"), nested]
            )
            .expect("dig"),
            text("fallback")
        );
    }

    #[test]
    fn dig_returns_a_typed_default_and_a_typed_value() {
        // The default is required, and it comes back with its own type: a
        // missing key over a numeric default yields the number, not its text.
        let entries = map(&[("a", number(1.0))]);
        assert_eq!(
            helper("dig", &[text("missing"), number(42.0), entries.clone()]).expect("dig"),
            number(42.0)
        );
        // The last step may return a non-map, and it keeps its type too.
        assert_eq!(
            helper("dig", &[text("a"), text("nope"), entries.clone()]).expect("dig"),
            number(1.0)
        );
        // A path that ends on a map falls back rather than returning the map.
        let ending = map(&[("a", map(&[("b", text("c"))]))]);
        assert_eq!(
            helper(
                "dig",
                &[text("a"), text("b"), text("c"), text("nope"), ending]
            )
            .expect("dig"),
            text("nope")
        );
        assert!(matches!(
            helper("dig", &[text("a"), text("b")]).expect_err("two arguments"),
            Error::WrongArgumentCount { .. }
        ));
    }

    #[test]
    fn merge_keeps_the_destination() {
        // fixtures/sprig/upstream_parity.json[165]:
        // {{ $d := dict "key" "old" }}{{ get (mustMerge $d (dict "next" "new")) "next" }}
        // renders `new`: the source contributes the key the destination lacks.
        let destination = map(&[("key", text("old"))]);
        let merged = helper(
            "merge",
            &[destination.clone(), map(&[("next", text("new"))])],
        )
        .expect("merge");
        assert_eq!(
            helper("get", &[merged, text("next")]).expect("get"),
            text("new")
        );
        // The destination is the first argument and wins a contested key.
        let merged = helper(
            "merge",
            &[destination.clone(), map(&[("key", text("new"))])],
        )
        .expect("merge");
        assert_eq!(
            helper("get", &[merged, text("key")]).expect("get"),
            text("old")
        );
        // Nothing is modified in place.
        assert_eq!(destination, map(&[("key", text("old"))]));
    }

    #[test]
    fn merge_descends_into_maps_it_finds() {
        // SprigUpstreamParityTests.MergeMutatesAndDeepMergesItsUpstreamDestination:
        // merging {"one": {"right": 3}, "two": 2} into {"one": {"left": 1}} leaves
        // both `one.left` and `one.right` reachable, and adds `two`.
        let destination = map(&[("one", map(&[("left", number(1.0))]))]);
        let source = map(&[
            ("one", map(&[("right", number(3.0))])),
            ("two", number(2.0)),
        ]);
        let merged = helper("merge", &[destination, source]).expect("merge");
        assert_eq!(merged.render(), "map[one:map[left:1 right:3] two:2]");
    }

    #[test]
    fn merge_overwrite_lets_the_source_win() {
        // SprigUpstreamParityTests.MergeOverwriteSharesNestedMapsUntilDeepCopyMatchesUpstream:
        // `mergeOverwrite $target $two` leaves `foo.bar` as `baz2` and `qux` as
        // `false`, where `merge` would have kept `baz` and `true`.
        let destination = map(&[
            ("foo", map(&[("bar", text("baz"))])),
            ("qux", Value::Bool(true)),
        ]);
        let source = map(&[
            ("foo", map(&[("bar", text("baz2"))])),
            ("qux", Value::Bool(false)),
        ]);
        assert_eq!(
            helper("mergeOverwrite", &[destination.clone(), source.clone()])
                .expect("mergeOverwrite"),
            map(&[
                ("foo", map(&[("bar", text("baz2"))])),
                ("qux", Value::Bool(false))
            ])
        );
        // The same inputs under `merge` keep everything the destination had.
        assert_eq!(
            helper("merge", &[destination, source]).expect("merge"),
            map(&[
                ("foo", map(&[("bar", text("baz"))])),
                ("qux", Value::Bool(true))
            ])
        );
    }

    #[test]
    fn merge_accepts_several_sources_and_needs_only_a_destination() {
        let destination = map(&[("a", number(1.0))]);
        let merged = helper(
            "merge",
            &[
                destination.clone(),
                map(&[("b", number(2.0))]),
                map(&[("c", number(3.0))]),
            ],
        )
        .expect("merge");
        assert_eq!(merged.render(), "map[a:1 b:2 c:3]");
        // `MergeMaps` needs one argument at least, and the destination must be a map.
        assert_eq!(
            helper("merge", std::slice::from_ref(&destination)).expect("merge"),
            destination
        );
        assert!(matches!(
            helper("merge", &[]).expect_err("no arguments"),
            Error::WrongArgumentCount { .. }
        ));
        assert!(matches!(
            helper("merge", &[text("nope")]).expect_err("scalar"),
            Error::InvalidArgument { .. }
        ));
    }

    #[test]
    fn deep_copy_is_equal_and_independent() {
        // SprigUpstreamParityTests.DeepCopyDoesNotShareNestedMaps writes `changed`
        // into the copy's nested map and the original still reads `original`. A
        // `Value` cannot be written through at all, so what that test protects is
        // the sharing of structure: the copy is a tree of its own, and a map
        // derived from it is a different value from the original's.
        let original = map(&[("nested", map(&[("value", text("original"))]))]);
        let copy = helper("deepCopy", std::slice::from_ref(&original)).expect("deepCopy");
        assert_eq!(
            helper("deepEqual", &[copy.clone(), original.clone()]).expect("deepEqual"),
            Value::Bool(true)
        );
        // Reaching into the copy and setting a key cannot reach the original.
        let nested = helper("get", &[copy.clone(), text("nested")]).expect("get");
        let changed = helper("set", &[nested, text("value"), text("changed")]).expect("set");
        assert_eq!(changed.render(), "map[value:changed]");
        assert_eq!(copy.render(), "map[nested:map[value:original]]");
        assert_eq!(original.render(), "map[nested:map[value:original]]");
    }

    #[test]
    fn deep_copy_rebuilds_lists_and_scalars() {
        let list = Value::List(vec![
            number(1.0),
            text("two"),
            Value::Bool(false),
            Value::Null,
        ]);
        let copy = helper("deepCopy", std::slice::from_ref(&list)).expect("deepCopy");
        assert_eq!(copy, list);
        // An empty container copies to an empty container.
        assert_eq!(
            helper("deepCopy", &[Value::List(vec![])]).expect("deepCopy"),
            Value::List(vec![])
        );
    }

    #[test]
    fn deep_equal_compares_structurally() {
        // fixtures/sprig/upstream_parity.json[155]:
        // {{ deepEqual (list 1 2) (list 1 2) }} renders `true`.
        assert_eq!(
            helper(
                "deepEqual",
                &[
                    Value::List(vec![number(1.0), number(2.0)]),
                    Value::List(vec![number(1.0), number(2.0)])
                ]
            )
            .expect("deepEqual"),
            Value::Bool(true)
        );
        // Order and length both matter.
        assert_eq!(
            helper(
                "deepEqual",
                &[
                    Value::List(vec![number(1.0), number(2.0)]),
                    Value::List(vec![number(2.0), number(1.0)])
                ]
            )
            .expect("deepEqual"),
            Value::Bool(false)
        );
        // Nested maps compare by content, and a missing key is a difference.
        let left = map(&[("a", map(&[("b", text("c"))]))]);
        let right = map(&[("a", map(&[("b", text("c"))]))]);
        let different = map(&[("a", map(&[]))]);
        assert_eq!(
            helper("deepEqual", &[left.clone(), right]).expect("deepEqual"),
            Value::Bool(true)
        );
        assert_eq!(
            helper("deepEqual", &[left, different]).expect("deepEqual"),
            Value::Bool(false)
        );
        // `Equal` compares kinds first, so the string "1" is not the number 1.
        assert_eq!(
            helper("deepEqual", &[text("1"), number(1.0)]).expect("deepEqual"),
            Value::Bool(false)
        );
        assert_eq!(
            helper("deepEqual", &[Value::Null, Value::Null]).expect("deepEqual"),
            Value::Bool(true)
        );
    }
}
