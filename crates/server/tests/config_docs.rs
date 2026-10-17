//! Verifies and regenerates `config.schema.json`, `config.default.toml`, and
//! `docs/modules/ROOT/partials/configuration-keys.adoc` from `src/config.rs`.

use ito::config::Config;
use serde_json::{Map, Value};

const SCHEMA: &str = "config.schema.json";
const DEFAULTS: &str = "config.default.toml";
const REFERENCE: &str = "docs/modules/ROOT/partials/configuration-keys.adoc";

#[test]
fn generated_config_files_are_current() {
    let schema = build_schema();
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let update = std::env::var_os("UPDATE_CONFIG_DOCS").is_some();
    for (path, text) in [
        (
            SCHEMA,
            serde_json::to_string_pretty(&schema).unwrap() + "\n",
        ),
        (DEFAULTS, render_defaults(&schema)),
        (REFERENCE, render_reference(&schema)),
    ] {
        let path = format!("{root}/{path}");
        if update {
            std::fs::write(&path, &text).unwrap();
        }
        let published = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            published == text,
            "{path} is stale; run `just generate-config`"
        );
    }
}

#[test]
fn defaults_file_parses_as_a_configuration() {
    let text = render_defaults(&build_schema());
    toml::from_str::<Config>(&text).unwrap();
}

/// Verifies that `config.sample.toml` does not set any key to its default value.
#[test]
fn sample_sets_no_key_to_its_default() {
    let schema = build_schema();
    let sample: toml::Table = toml::from_str(include_str!("../../../config.sample.toml")).unwrap();
    let mut pinned = Vec::new();
    for section in collect_sections(&schema) {
        for table in find_tables_at(&sample, &section.path) {
            for key in &section.keys {
                let set = table
                    .get(key.name)
                    .map(|v| serde_json::to_value(v).unwrap());
                if set.is_some() && set.as_ref() == section.default(key) {
                    let name = section.name().map_or(String::new(), |n| format!("{n}."));
                    pinned.push(format!("{name}{}", key.name));
                }
            }
        }
    }
    assert!(
        pinned.is_empty(),
        "config.sample.toml repeats defaults: {pinned:?}"
    );
}

// --- Schema extraction ---

/// Builds the JSON Schema for [`Config`] with single line breaks inside descriptions unwrapped.
fn build_schema() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(Config)).unwrap();
    unwrap_descriptions(&mut schema);
    schema
}

fn unwrap_descriptions(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                match (k.as_str(), v) {
                    ("description", Value::String(s)) => *s = unwrap_paragraphs(s),
                    (_, v) => unwrap_descriptions(v),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(unwrap_descriptions),
        _ => {}
    }
}

fn unwrap_paragraphs(text: &str) -> String {
    text.split("\n\n")
        .map(|p| p.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Configuration key extracted from a JSON Schema object definition.
struct Key<'a> {
    name: &'a str,
    schema: &'a Map<String, Value>,
    required: bool,
}

impl<'a> Key<'a> {
    fn description(&self) -> &'a str {
        self.schema
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    fn default(&self) -> Option<&'a Value> {
        self.schema.get("default").filter(|v| !v.is_null())
    }

    fn example(&self) -> Option<&'a Value> {
        self.schema
            .get("examples")
            .and_then(Value::as_array)
            .and_then(|e| e.first())
    }
}

/// Configuration table section (top-level, named section such as `[oidc]`, map section such as
/// `[interfaces.NAME]`, or array of tables such as `[[interfaces.NAME.pools]]`).
struct Section<'a> {
    /// Path segments for the table header (`NAME` represents a map key placeholder).
    path: Vec<&'a str>,
    /// Whether the section is rendered as an array of tables (`[[path]]`).
    array: bool,
    description: &'a str,
    /// Whether the section is optional and commented out in `config.default.toml`.
    optional: bool,
    keys: Vec<Key<'a>>,
    /// Default values supplied by the parent property, if any.
    defaults: Option<&'a Map<String, Value>>,
}

impl<'a> Section<'a> {
    fn name(&self) -> Option<String> {
        (!self.path.is_empty()).then(|| self.path.join("."))
    }

    fn header(&self) -> Option<String> {
        let name = self.name()?;
        Some(if self.array {
            format!("[[{name}]]")
        } else {
            format!("[{name}]")
        })
    }

    fn default(&self, key: &Key<'a>) -> Option<&'a Value> {
        match self.defaults {
            Some(d) => d.get(key.name).filter(|v| !v.is_null()),
            None => key.default(),
        }
    }
}

/// Resolves a `$ref` string against `$defs` if it points to an object table definition.
fn resolve_table_ref<'a>(defs: &'a Value, reference: Option<&Value>) -> Option<&'a Value> {
    let name = reference?.as_str()?.strip_prefix("#/$defs/")?;
    Some(&defs[name]).filter(|def| def.get("properties").is_some())
}

/// Inspects a property schema to determine if it holds a nested table, map of tables, or array of
/// tables.
fn extract_table_holder<'a>(
    defs: &'a Value,
    key: &Map<String, Value>,
) -> Option<(&'a Value, Holder)> {
    let read_nested_ref = |k: &str| key.get(k).and_then(|v| v.get("$ref"));
    if let Some(def) = resolve_table_ref(defs, key.get("$ref")) {
        return Some((def, Holder::Table { optional: false }));
    }
    let any_of = key.get("anyOf").and_then(Value::as_array);
    if let Some(def) = any_of.and_then(|a| {
        a.iter()
            .find_map(|a| resolve_table_ref(defs, a.get("$ref")))
    }) {
        return Some((def, Holder::Table { optional: true }));
    }
    if let Some(def) = resolve_table_ref(defs, read_nested_ref("additionalProperties")) {
        return Some((def, Holder::Map));
    }
    resolve_table_ref(defs, read_nested_ref("items")).map(|def| (def, Holder::Array))
}

enum Holder {
    Table { optional: bool },
    Map,
    Array,
}

fn extract_keys(object: &Value) -> Vec<Key<'_>> {
    let required: Vec<&str> = object["required"]
        .as_array()
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    object["properties"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, s)| Key {
            name,
            schema: s.as_object().expect("property schema"),
            required: required.contains(&name.as_str()),
        })
        .collect()
}

/// Recursively collects `section` and all nested table sections in depth-first order.
fn collect_sections_at<'a>(
    defs: &'a Value,
    object: &'a Value,
    mut section: Section<'a>,
    out: &mut Vec<Section<'a>>,
) {
    let mut nested = Vec::new();
    for key in extract_keys(object) {
        let Some((def, holder)) = extract_table_holder(defs, key.schema) else {
            section.keys.push(key);
            continue;
        };
        let description = match key.description() {
            "" => def["description"].as_str().unwrap_or_default(),
            own => own,
        };
        let mut path = section.path.clone();
        path.push(key.name);
        let (array, optional, defaults) = match holder {
            Holder::Table { optional } => {
                (false, optional, key.default().and_then(Value::as_object))
            }
            Holder::Map => {
                path.push("NAME");
                (false, true, None)
            }
            Holder::Array => (true, true, None),
        };
        nested.push((
            def,
            Section {
                path,
                array,
                description,
                optional: optional || section.optional,
                keys: Vec::new(),
                defaults,
            },
        ));
    }
    out.push(section);
    for (def, section) in nested {
        collect_sections_at(defs, def, section, out);
    }
}

fn collect_sections(schema: &Value) -> Vec<Section<'_>> {
    let top = Section {
        path: Vec::new(),
        array: false,
        description: "",
        optional: false,
        keys: Vec::new(),
        defaults: None,
    };
    let mut out = Vec::new();
    collect_sections_at(&schema["$defs"], schema, top, &mut out);
    out
}

/// Finds all TOML tables in `table` matching `path`, expanding `NAME` across map entries.
fn find_tables_at<'a>(table: &'a toml::Table, path: &[&str]) -> Vec<&'a toml::Table> {
    let Some((first, rest)) = path.split_first() else {
        return vec![table];
    };
    let children: Vec<&toml::Value> = match *first {
        "NAME" => table.values().collect(),
        name => table.get(name).into_iter().collect(),
    };
    children
        .into_iter()
        .flat_map(|v| match v {
            toml::Value::Table(t) => vec![t],
            toml::Value::Array(items) => items.iter().filter_map(toml::Value::as_table).collect(),
            _ => Vec::new(),
        })
        .flat_map(|t| find_tables_at(t, rest))
        .collect()
}

// --- TOML and AsciiDoc rendering ---

fn format_toml_value(v: &Value) -> String {
    toml::Value::try_from(v).unwrap().to_string()
}

fn append_comment(out: &mut String, text: &str, prefix: &str) {
    for paragraph in text.split("\n\n") {
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            if !line.is_empty() && prefix.len() + line.len() + word.len() + 3 > 100 {
                out.push_str(&format!("{prefix}# {line}\n"));
                line.clear();
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        if !line.is_empty() {
            out.push_str(&format!("{prefix}# {line}\n"));
        }
    }
}

/// Renders `config.default.toml` with default values and commented-out examples.
fn render_defaults(schema: &Value) -> String {
    let mut out = String::from(
        "# Default values, or examples for keys without a default.\n\
         # Generated from crates/server/src/config.rs by `just generate-config`.\n",
    );
    for section in collect_sections(schema) {
        let off = if section.optional { "# " } else { "" };
        if let Some(header) = section.header() {
            out.push('\n');
            append_comment(&mut out, section.description, "");
            out.push_str(&format!("{off}{header}\n"));
        }
        for key in &section.keys {
            out.push('\n');
            append_comment(&mut out, key.description(), "");
            match (key.required, section.default(key), key.example()) {
                (false, Some(v), _) => {
                    out.push_str(&format!("{off}{} = {}\n", key.name, format_toml_value(v)))
                }
                (required, _, Some(v)) => {
                    if required {
                        out.push_str("# Required.\n");
                    }
                    out.push_str(&format!("# {} = {}\n", key.name, format_toml_value(v)));
                }
                _ => {}
            }
        }
    }
    out
}

/// Renders the AsciiDoc reference tables for `configuration.adoc`.
fn render_reference(schema: &Value) -> String {
    let mut out = String::from(
        "// Generated from crates/server/src/config.rs by `just generate-config`; edit the doc comments there.\n",
    );
    for section in collect_sections(schema) {
        let (anchor, title) = match (section.name(), section.header()) {
            (Some(name), Some(header)) => (
                name.replace(".NAME", "").replace('.', "-"),
                format!("`{header}`"),
            ),
            _ => ("top-level".to_string(), "Top level".to_string()),
        };
        out.push_str(&format!("\n[#{anchor}]\n== {title}\n\n"));
        if !section.description.is_empty() {
            out.push_str(&format!("{}\n\n", section.description));
        }
        out.push_str("[cols=\"1,1,3\"]\n|===\n|Key |Default |Meaning\n");
        for key in &section.keys {
            let default = match (key.required, section.default(key)) {
                (true, _) => "required".to_string(),
                (false, Some(v)) => format!("`{}`", format_toml_value(v)),
                (false, None) => "unset".to_string(),
            };
            let example = match (
                key.required || section.default(key).is_none(),
                key.example(),
            ) {
                (true, Some(v)) => format!(" For example `{}`.", format_toml_value(v)),
                _ => String::new(),
            };
            out.push_str(&format!(
                "\n|`{}`\n|{default}\n|{}{example}\n",
                key.name,
                key.description()
            ));
        }
        out.push_str("|===\n");
    }
    out
}
