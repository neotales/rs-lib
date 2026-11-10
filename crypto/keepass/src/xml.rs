use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Cursor, Read};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::read::GzDecoder;
use quick_xml::Reader;
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use zeroize::Zeroize;

use crate::crypto::InnerCipher;
use crate::error::KdbxError;
use crate::limits::KdbxReadLimits;
use crate::model::{
    Attachment, AutoType, AutoTypeAssociation, BinaryPool, CustomData, CustomIcon, DeletedObject,
    Entry, Field, Group, KeePassDatabase, KeePassMeta, KeePassTimes, ProtectedValue,
};
use crate::primitives::{KdbxColor, KdbxTimestamp, KdbxUuid};
use crate::wire::InnerHeader;

#[derive(Clone, Debug)]
struct XmlNode {
    name: String,
    attrs: BTreeMap<String, String>,
    text: String,
    children: Vec<XmlNode>,
}

fn parse_tree(data: &[u8], limits: &KdbxReadLimits) -> Result<XmlNode, KdbxError> {
    if data.len() as u64 > limits.max_xml_chars {
        return Err(KdbxError::resource_limit(
            "KDBX XML exceeds the configured limit",
        ));
    }
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(false);
    reader.config_mut().enable_all_checks(true);
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root = None;
    let mut buffer = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buffer)
            .map_err(|_| KdbxError::malformed("invalid KDBX XML"))?
        {
            Event::Start(start) => {
                if stack.len() >= limits.max_xml_depth {
                    return Err(KdbxError::resource_limit(
                        "KDBX XML depth exceeds the configured limit",
                    ));
                }
                stack.push(node_from_start(&start)?);
            }
            Event::Empty(start) => {
                let node = node_from_start(&start)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    root = Some(node);
                }
            }
            Event::Text(text) => {
                if let Some(parent) = stack.last_mut() {
                    // `Implicit1_0` is the version KDBX documents are written
                    // as and the only variant that is byte-for-byte what this
                    // call did before quick-xml made the version explicit: the
                    // older no-argument `xml_content()` was exactly the XML 1.0
                    // EOL normalization, and `Explicit1_1` would additionally
                    // treat NEL and LINE SEPARATOR as line ends. KDBX content
                    // is base64 and prose, so a lone `\r` in a note is the only
                    // case the two differ on, and XML 1.0 is the version the
                    // writer emits.
                    //
                    // quick-xml 0.42 makes this infallible: the reader validates
                    // UTF-8 when it builds the event, so `xml_content` returns the
                    // text directly instead of a `Result`. The `?` and its
                    // error arm are gone because the failure they caught can no
                    // longer be observed here.
                    parent
                        .text
                        .push_str(&text.xml_content(XmlVersion::Implicit1_0));
                }
            }
            Event::CData(data) => {
                if let Some(parent) = stack.last_mut() {
                    parent.text.push_str(data.as_ref());
                }
            }
            Event::End(_) => {
                let node = stack
                    .pop()
                    .ok_or_else(|| KdbxError::malformed("unbalanced KDBX XML"))?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    root = Some(node);
                }
            }
            Event::GeneralRef(reference) => {
                // 0.42 removed `BytesRef::decode`: event payloads are `Cow<str>`
                // and deref to `&str`, so the decoded text is read directly. The
                // reader already rejected non-UTF-8 input when it built the
                // event, which is what `decode()` used to re-check here.
                let decoded = reference.as_ref();
                let resolved = if let Some(character) = reference
                    .resolve_char_ref()
                    .map_err(|_| KdbxError::malformed("invalid KDBX XML character entity"))?
                {
                    character.to_string()
                } else if let Some(value) = quick_xml::escape::resolve_predefined_entity(decoded) {
                    value.to_owned()
                } else {
                    return Err(KdbxError::unsupported(
                        "external entities are not permitted in KDBX XML",
                    ));
                };
                if let Some(parent) = stack.last_mut() {
                    parent.text.push_str(&resolved);
                }
            }
            Event::DocType(_) => {
                return Err(KdbxError::unsupported("DTDs are not permitted in KDBX XML"));
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !stack.is_empty() {
        return Err(KdbxError::malformed("unterminated KDBX XML"));
    }
    root.ok_or_else(|| KdbxError::malformed("KDBX XML has no document element"))
}

fn node_from_start(start: &BytesStart<'_>) -> Result<XmlNode, KdbxError> {
    let mut attrs = BTreeMap::new();
    for attr in start.attributes().with_checks(true) {
        let attr = attr.map_err(|_| KdbxError::malformed("invalid KDBX XML attribute"))?;
        let key = attr.key.as_ref().to_owned();
        // `normalized_value` is the non-deprecated spelling of the old
        // `unescape_value`, and quick-xml 0.42 keeps it with the same
        // signature: it still returns a `Result`, so the error arm stays. What
        // it does is unchanged XML attribute-value normalization, which turns
        // tab and newline into a space and expands the five predefined entities.
        // KDBX attribute values are `Protected`, `ID`, `Ref`, `Compressed`,
        // `ProtectInMemory` and `Hash` — tokens that none of that touches.
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| KdbxError::malformed("invalid KDBX XML attribute"))?
            .into_owned();
        if attrs.insert(key, value).is_some() {
            return Err(KdbxError::malformed("duplicate KDBX XML attribute"));
        }
    }
    Ok(XmlNode {
        name: start.name().as_ref().to_owned(),
        attrs,
        text: String::new(),
        children: Vec::new(),
    })
}

fn child<'a>(node: &'a XmlNode, name: &str) -> Option<&'a XmlNode> {
    node.children.iter().find(|child| child.name == name)
}
fn children<'a>(node: &'a XmlNode, name: &str) -> impl Iterator<Item = &'a XmlNode> {
    node.children.iter().filter(move |child| child.name == name)
}
fn text<'a>(node: &'a XmlNode, name: &str) -> Option<&'a str> {
    child(node, name).map(|child| child.text.as_str())
}
fn required_text(node: &XmlNode, name: &str) -> Result<String, KdbxError> {
    text(node, name)
        .map(str::to_owned)
        .ok_or_else(|| KdbxError::malformed(format!("missing XML element {name}")))
}
fn parse_uuid(node: &XmlNode, name: &str) -> Result<KdbxUuid, KdbxError> {
    KdbxUuid::from_base64(&required_text(node, name)?)
}

fn has_protected_payload(node: &XmlNode) -> bool {
    node.attrs.iter().any(|(name, value)| {
        name == "Protected" && (value == "True" || value == "true" || value == "1")
    }) || node
        .children
        .iter()
        .any(|child| has_protected_payload(child))
}

fn analyze_losslessness(root: &XmlNode) -> Result<bool, KdbxError> {
    fn allowed_children(node: &XmlNode) -> &'static [&'static str] {
        match node.name.as_str() {
            "KeePassFile" => &["Meta", "Root"],
            "Meta" => &[
                "Generator",
                "Times",
                "HeaderHash",
                "SettingsChanged",
                "DatabaseName",
                "DatabaseNameChanged",
                "DatabaseDescription",
                "DatabaseDescriptionChanged",
                "DefaultUserName",
                "DefaultUserNameChanged",
                "MaintenanceHistoryDays",
                "Color",
                "MasterKeyChanged",
                "MasterKeyChangeRec",
                "MasterKeyChangeForce",
                "MasterKeyChangeForceOnce",
                "MemoryProtection",
                "CustomIcons",
                "RecycleBinEnabled",
                "RecycleBinUUID",
                "RecycleBinChanged",
                "EntryTemplatesGroup",
                "EntryTemplatesGroupChanged",
                "LastSelectedGroup",
                "LastTopVisibleGroup",
                "HistoryMaxItems",
                "HistoryMaxSize",
                "Binaries",
                "CustomData",
            ],
            "MemoryProtection" => &[
                "ProtectTitle",
                "ProtectUserName",
                "ProtectPassword",
                "ProtectURL",
                "ProtectNotes",
            ],
            "CustomIcons" => &["Icon"],
            "Icon" => &["UUID", "Data", "Name", "LastModificationTime"],
            "Binaries" => &["Binary"],
            "CustomData" => &["Item"],
            "Item" => &["Key", "Value", "LastModificationTime"],
            "Root" => &["Group", "DeletedObjects"],
            "DeletedObjects" => &["DeletedObject"],
            "DeletedObject" => &["UUID", "DeletionTime"],
            "Group" => &[
                "UUID",
                "Name",
                "Notes",
                "IconID",
                "CustomIconUUID",
                "IsExpanded",
                "DefaultAutoTypeSequence",
                "EnableAutoType",
                "EnableSearching",
                "LastTopVisibleEntry",
                "PreviousParentGroup",
                "Times",
                "CustomData",
                "Tags",
                "Entry",
                "Group",
            ],
            "Entry" => &[
                "UUID",
                "Name",
                "OverrideURL",
                "IconID",
                "CustomIconUUID",
                "ForegroundColor",
                "BackgroundColor",
                "QualityCheck",
                "PreviousParentGroup",
                "Tags",
                "Times",
                "String",
                "Binary",
                "AutoType",
                "CustomData",
                "History",
            ],
            "Times" => &[
                "CreationTime",
                "LastModificationTime",
                "LastAccessTime",
                "ExpiryTime",
                "Expires",
                "UsageCount",
                "LocationChanged",
            ],
            "String" | "Binary" => &["Key", "Value"],
            "AutoType" => &[
                "Enabled",
                "Obfuscated",
                "DataTransferObfuscation",
                "DefaultSequence",
                "Association",
            ],
            "Association" => &["Window", "Keystrokes", "KeystrokeSequence"],
            "History" => &["Entry"],
            _ => &[],
        }
    }

    fn allowed_attributes(node: &XmlNode, parent: Option<&str>) -> &'static [&'static str] {
        match (node.name.as_str(), parent) {
            ("Data", Some("Icon")) => &["Protected"],
            ("Binary", Some("Binaries")) => &["ID", "Compressed", "Protected"],
            ("Value", Some("String")) => &["Protected", "ProtectInMemory"],
            ("Value", Some("Binary")) => &["Ref", "Protected"],
            _ => &[],
        }
    }

    fn repeatable(parent: &str, child: &str) -> bool {
        matches!(
            (parent, child),
            ("Group", "Entry")
                | ("Group", "Group")
                | ("Entry", "String")
                | ("Entry", "Binary")
                | ("History", "Entry")
                | ("CustomData", "Item")
                | ("CustomIcons", "Icon")
                | ("Binaries", "Binary")
                | ("DeletedObjects", "DeletedObject")
                | ("AutoType", "Association")
        )
    }

    fn visit(node: &XmlNode, parent: Option<&str>, lossless: &mut bool) -> Result<(), KdbxError> {
        let children = allowed_children(node);
        let mut seen = BTreeMap::new();
        for child_node in &node.children {
            if !children.contains(&child_node.name.as_str()) {
                *lossless = false;
                if has_protected_payload(child_node) {
                    return Err(KdbxError::unsupported(
                        "protected KDBX XML extension data is unsupported",
                    ));
                }
                continue;
            }
            if !repeatable(node.name.as_str(), child_node.name.as_str())
                && seen.insert(child_node.name.as_str(), ()).is_some()
            {
                *lossless = false;
            }
            visit(child_node, Some(&node.name), lossless)?;
        }
        let attributes = allowed_attributes(node, parent);
        if node
            .attrs
            .keys()
            .any(|attribute| !attributes.contains(&attribute.as_str()))
        {
            *lossless = false;
        }
        Ok(())
    }

    let mut lossless = true;
    visit(root, None, &mut lossless)?;
    Ok(lossless)
}

fn parse_timestamp(value: &str) -> Result<KdbxTimestamp, KdbxError> {
    if let Some(bytes) = STANDARD
        .decode(value)
        .ok()
        .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
    {
        return Ok(KdbxTimestamp(i64::from_le_bytes(bytes)));
    }
    let timestamp =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .map_err(|_| KdbxError::malformed("invalid KDBX XML timestamp"))?;
    Ok(KdbxTimestamp::from_unix_seconds(timestamp.unix_timestamp()))
}

pub(crate) fn parse_database(
    data: &[u8],
    inner: &InnerHeader,
    binaries: &[(Vec<u8>, bool)],
    inner_stream_offset: usize,
    legacy_binary_references: bool,
    expected_header_hash: Option<&[u8]>,
    limits: &KdbxReadLimits,
) -> Result<KeePassDatabase, KdbxError> {
    let root = parse_tree(data, limits)?;
    if root.name != "KeePassFile" {
        return Err(KdbxError::malformed("KDBX XML root must be KeePassFile"));
    }
    let mut database = KeePassDatabase::default();
    database.can_save_losslessly = analyze_losslessness(&root)?;
    for (value, protected) in binaries {
        database.binary_pool.add(value.clone(), *protected);
    }
    let mut legacy_references = BTreeMap::new();
    let mut stream = InnerCipher::new(inner.stream_id, &inner.stream_key)?;
    stream.advance(inner_stream_offset);
    if let Some(meta) = child(&root, "Meta") {
        parse_meta(
            meta,
            &mut stream,
            &mut database,
            &mut legacy_references,
            expected_header_hash,
            limits,
        )?;
    }
    let root_group =
        child(&root, "Root").ok_or_else(|| KdbxError::malformed("KDBX XML is missing Root"))?;
    let group = child(root_group, "Group")
        .ok_or_else(|| KdbxError::malformed("KDBX Root is missing Group"))?;
    database.root = parse_group(
        group,
        &mut stream,
        &mut database.binary_pool,
        &legacy_references,
        legacy_binary_references,
        limits,
    )?;
    if let Some(deleted) = child(root_group, "DeletedObjects") {
        for item in children(deleted, "DeletedObject") {
            database.deleted_objects.push(DeletedObject {
                id: parse_uuid(item, "UUID")?,
                deleted_at: parse_timestamp(&required_text(item, "DeletionTime")?)?,
            });
        }
    }
    resolve_attachments(&database.root, &database.binary_pool)?;
    Ok(database)
}

fn parse_meta(
    node: &XmlNode,
    stream: &mut InnerCipher,
    database: &mut KeePassDatabase,
    legacy_references: &mut BTreeMap<u32, usize>,
    expected_header_hash: Option<&[u8]>,
    limits: &KdbxReadLimits,
) -> Result<(), KdbxError> {
    let mut meta = KeePassMeta {
        generator: text(node, "Generator").unwrap_or_default().into(),
        name: text(node, "DatabaseName").unwrap_or_default().into(),
        description: text(node, "DatabaseDescription").unwrap_or_default().into(),
        default_username: text(node, "DefaultUserName").unwrap_or_default().into(),
        ..KeePassMeta::default()
    };
    if let Some(value) = text(node, "HeaderHash") {
        let actual = STANDARD
            .decode(value)
            .map_err(|_| KdbxError::malformed("invalid KDBX HeaderHash"))?;
        if let Some(expected) = expected_header_hash {
            if !constant_time_equal(&actual, expected) {
                return Err(KdbxError::new(
                    crate::KdbxFailureKind::Authentication,
                    "KDBX 3 header hash validation failed",
                ));
            }
        }
    } else if expected_header_hash.is_some() {
        return Err(KdbxError::malformed(
            "KDBX 3 XML is missing the required HeaderHash",
        ));
    }
    if let Some(times) = child(node, "Times") {
        meta.times = parse_times(times)?;
    }
    if let Some(value) = text(node, "SettingsChanged") {
        meta.settings_changed = Some(parse_timestamp(value)?);
    }
    if let Some(value) = text(node, "DatabaseNameChanged") {
        meta.database_name_changed = Some(parse_timestamp(value)?);
    }
    if let Some(value) = text(node, "DatabaseDescriptionChanged") {
        meta.database_description_changed = Some(parse_timestamp(value)?);
    }
    if let Some(value) = text(node, "DefaultUserNameChanged") {
        meta.default_username_changed = Some(parse_timestamp(value)?);
    }
    if let Some(value) = text(node, "MasterKeyChanged") {
        meta.master_key_changed = Some(parse_timestamp(value)?);
    }
    if let Some(value) = text(node, "MaintenanceHistoryDays") {
        meta.maintenance_history_days = value
            .parse()
            .map_err(|_| KdbxError::malformed("invalid MaintenanceHistoryDays"))?;
    }
    if let Some(value) = text(node, "Color") {
        meta.color = KdbxColor::parse(value)?;
    }
    if let Some(value) = text(node, "MasterKeyChangeRec") {
        meta.master_key_change_rec = value
            .parse()
            .map_err(|_| KdbxError::malformed("invalid MasterKeyChangeRec"))?;
    }
    if let Some(value) = text(node, "MasterKeyChangeForce") {
        meta.master_key_change_force = value
            .parse()
            .map_err(|_| KdbxError::malformed("invalid MasterKeyChangeForce"))?;
    }
    if let Some(value) = text(node, "MasterKeyChangeForceOnce") {
        meta.master_key_change_force_once = value == "True";
    }
    if let Some(value) = text(node, "RecycleBinUUID") {
        meta.recycle_bin_uuid = KdbxUuid::from_base64(value)?;
    }
    if let Some(value) = text(node, "RecycleBinChanged") {
        meta.recycle_bin_changed = Some(parse_timestamp(value)?);
    }
    if let Some(value) = text(node, "EntryTemplatesGroup") {
        meta.templates_uuid = KdbxUuid::from_base64(value)?;
    }
    if let Some(value) = text(node, "EntryTemplatesGroupChanged") {
        meta.templates_changed = Some(parse_timestamp(value)?);
    }
    if let Some(value) = text(node, "LastSelectedGroup") {
        meta.selected_group_uuid = KdbxUuid::from_base64(value)?;
    }
    if let Some(value) = text(node, "LastTopVisibleGroup") {
        meta.top_visible_group_uuid = KdbxUuid::from_base64(value)?;
    }
    if let Some(memory) = child(node, "MemoryProtection") {
        meta.memory_protection = true;
        meta.protect_password =
            text(memory, "ProtectPassword").is_some_and(|value| value == "True");
        meta.protect_title = text(memory, "ProtectTitle").is_some_and(|value| value == "True");
        meta.protect_username =
            text(memory, "ProtectUsername").is_some_and(|value| value == "True");
        meta.protect_url = text(memory, "ProtectURL").is_some_and(|value| value == "True");
        meta.protect_notes = text(memory, "ProtectNotes").is_some_and(|value| value == "True");
    }
    if let Some(value) = text(node, "HistoryMaxItems") {
        meta.history_max_items = value.parse().ok();
    }
    if let Some(value) = text(node, "HistoryMaxSize") {
        meta.history_max_size = value.parse().ok();
    }
    if let Some(value) = text(node, "RecycleBinEnabled") {
        meta.recycle_bin_enabled = value == "True";
    }
    if let Some(custom_data) = child(node, "CustomData") {
        meta.custom_data = parse_custom_data(custom_data, true)?;
    }
    if let Some(icons) = child(node, "CustomIcons") {
        for icon in children(icons, "Icon") {
            meta.custom_icons
                .push(parse_custom_icon(icon, stream, limits)?);
        }
    }
    if let Some(binaries) = child(node, "Binaries") {
        meta.legacy_binaries =
            parse_legacy_binaries(binaries, stream, database, legacy_references, limits)?;
    }
    database.meta = meta;
    Ok(())
}

fn parse_custom_icon(
    node: &XmlNode,
    stream: &mut InnerCipher,
    limits: &KdbxReadLimits,
) -> Result<CustomIcon, KdbxError> {
    let data =
        child(node, "Data").ok_or_else(|| KdbxError::malformed("custom icon is missing Data"))?;
    Ok(CustomIcon {
        uuid: parse_uuid(node, "UUID")?,
        data: decode_xml_binary(data, stream, limits)?,
        name: text(node, "Name").map(str::to_owned),
        last_modification: text(node, "LastModificationTime")
            .map(parse_timestamp)
            .transpose()?,
    })
}

fn parse_legacy_binaries(
    node: &XmlNode,
    stream: &mut InnerCipher,
    database: &mut KeePassDatabase,
    legacy_references: &mut BTreeMap<u32, usize>,
    limits: &KdbxReadLimits,
) -> Result<Vec<Vec<u8>>, KdbxError> {
    let mut seen_ids = BTreeMap::new();
    let mut decoded = Vec::new();
    let mut legacy = Vec::new();
    for binary in children(node, "Binary") {
        if database.binary_pool.len() + decoded.len() >= limits.max_binary_records {
            return Err(KdbxError::resource_limit(
                "legacy binary count exceeds the configured limit",
            ));
        }
        let id = binary
            .attrs
            .get("ID")
            .ok_or_else(|| KdbxError::malformed("legacy binary is missing ID"))?
            .parse::<u32>()
            .map_err(|_| KdbxError::malformed("invalid legacy binary ID"))?;
        if seen_ids.insert(id, ()).is_some() {
            return Err(KdbxError::malformed("duplicate legacy binary ID"));
        }
        let protected = xml_bool(binary, "Protected")?;
        let mut data = decode_xml_binary(binary, stream, limits)?;
        if xml_bool(binary, "Compressed")? {
            data = decompress_binary(&data, limits)?;
        }
        check_binary_size(data.len(), limits)?;
        legacy.push(data.clone());
        decoded.push((id, data, protected));
    }
    decoded.sort_by_key(|(id, _, _)| *id);
    for (id, data, protected) in decoded {
        let index = add_binary(&mut database.binary_pool, data, protected, limits)?;
        legacy_references.insert(id, index);
    }
    Ok(legacy)
}

fn decode_xml_binary(
    node: &XmlNode,
    stream: &mut InnerCipher,
    limits: &KdbxReadLimits,
) -> Result<Vec<u8>, KdbxError> {
    let mut data = STANDARD
        .decode(&node.text)
        .map_err(|_| KdbxError::malformed("invalid XML Base64"))?;
    check_binary_size(data.len(), limits)?;
    if xml_bool(node, "Protected")? {
        stream.transform(&mut data);
    }
    Ok(data)
}

fn parse_nullable_bool(value: &str) -> Result<Option<bool>, KdbxError> {
    match value {
        "Null" | "null" => Ok(None),
        "True" | "true" | "1" => Ok(Some(true)),
        "False" | "false" | "0" => Ok(Some(false)),
        _ => Err(KdbxError::malformed("invalid nullable KDBX XML boolean")),
    }
}

fn xml_bool(node: &XmlNode, name: &str) -> Result<bool, KdbxError> {
    match node.attrs.get(name) {
        None => Ok(false),
        Some(value) if value == "True" || value == "true" || value == "1" => Ok(true),
        Some(value) if value == "False" || value == "false" || value == "0" => Ok(false),
        Some(_) => Err(KdbxError::malformed("invalid KDBX XML boolean")),
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn check_binary_size(size: usize, limits: &KdbxReadLimits) -> Result<(), KdbxError> {
    if size as u64 > limits.max_binary_bytes {
        return Err(KdbxError::resource_limit(
            "KDBX binary exceeds the configured limit",
        ));
    }
    Ok(())
}

fn add_binary(
    pool: &mut BinaryPool,
    data: Vec<u8>,
    protected: bool,
    limits: &KdbxReadLimits,
) -> Result<usize, KdbxError> {
    if pool.len() >= limits.max_binary_records {
        return Err(KdbxError::resource_limit(
            "KDBX binary count exceeds the configured limit",
        ));
    }
    let total = pool.records().iter().fold(0usize, |total, record| {
        total.saturating_add(record.data.len())
    });
    if total as u64 + data.len() as u64 > limits.max_binary_bytes {
        return Err(KdbxError::resource_limit(
            "KDBX binary bytes exceed the configured limit",
        ));
    }
    Ok(pool.add(data, protected))
}

fn decompress_binary(input: &[u8], limits: &KdbxReadLimits) -> Result<Vec<u8>, KdbxError> {
    let decoder = GzDecoder::new(Cursor::new(input));
    let mut output = Vec::new();
    decoder
        .take(limits.max_binary_bytes.saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|_| KdbxError::malformed("invalid compressed KDBX binary"))?;
    check_binary_size(output.len(), limits)?;
    Ok(output)
}

fn parse_times(node: &XmlNode) -> Result<KeePassTimes, KdbxError> {
    let mut times = KeePassTimes::default();
    for (name, target) in [
        ("CreationTime", &mut times.created),
        ("LastModificationTime", &mut times.modified),
        ("LastAccessTime", &mut times.accessed),
        ("ExpiryTime", &mut times.expires),
        ("LocationChanged", &mut times.location_changed),
    ] {
        if let Some(value) = text(node, name) {
            *target = parse_timestamp(value)?;
        }
    }
    if let Some(value) = text(node, "Expires") {
        times.expires_enabled = value == "True";
    }
    if let Some(value) = text(node, "UsageCount") {
        times.usage_count = value
            .parse()
            .map_err(|_| KdbxError::malformed("invalid UsageCount"))?;
    }
    Ok(times)
}

fn parse_group(
    node: &XmlNode,
    stream: &mut InnerCipher,
    pool: &mut BinaryPool,
    legacy_references: &BTreeMap<u32, usize>,
    legacy_binary_references: bool,
    limits: &KdbxReadLimits,
) -> Result<Group, KdbxError> {
    ensure_children_allowed(
        node,
        &[
            "UUID",
            "Name",
            "Notes",
            "IconID",
            "CustomIconUUID",
            "IsExpanded",
            "DefaultAutoTypeSequence",
            "EnableAutoType",
            "EnableSearching",
            "LastTopVisibleEntry",
            "PreviousParentGroup",
            "Times",
            "CustomData",
            "Tags",
            "Entry",
            "Group",
        ],
    )?;
    let mut group = Group::new(text(node, "Name").unwrap_or("Group"));
    if let Some(value) = text(node, "UUID") {
        group.id = KdbxUuid::from_base64(value)?;
    }
    if let Some(value) = text(node, "Notes") {
        group.notes = value.into();
    }
    if let Some(value) = text(node, "IconID") {
        group.icon_id = value
            .parse()
            .map_err(|_| KdbxError::malformed("invalid group IconID"))?;
    }
    if let Some(value) = text(node, "Tags") {
        group.tags = value
            .split(';')
            .filter(|tag| !tag.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(value) = text(node, "IsExpanded") {
        group.is_expanded = value == "True";
    }
    if let Some(value) = text(node, "DefaultAutoTypeSequence") {
        group.default_auto_type_sequence = value.into();
    }
    if let Some(value) = text(node, "EnableAutoType") {
        group.enable_auto_type = parse_nullable_bool(value)?;
    }
    if let Some(value) = text(node, "EnableSearching") {
        group.enable_searching = parse_nullable_bool(value)?;
    }
    if let Some(value) = text(node, "LastTopVisibleEntry") {
        group.last_top_visible_entry_id = KdbxUuid::from_base64(value)?;
    }
    if let Some(value) = text(node, "PreviousParentGroup") {
        group.previous_parent_group_id = KdbxUuid::from_base64(value)?;
    }
    if let Some(times) = child(node, "Times") {
        group.times = parse_times(times)?;
    }
    if let Some(custom) = child(node, "CustomData") {
        group.custom_data = parse_custom_data(custom, false)?;
    }
    // KDBX 4 inner protected streams are consumed in document order, so the
    // reader must visit `Entry` and `Group` children in exactly the order they
    // appear. Grouping the two element kinds by name would desynchronize the
    // inner cipher for any document that mixes entries and child groups.
    for child_node in &node.children {
        if child_node.name == "Group" {
            group.groups.push(parse_group(
                child_node,
                stream,
                pool,
                legacy_references,
                legacy_binary_references,
                limits,
            )?);
        } else if child_node.name == "Entry" {
            group.entries.push(parse_entry(
                child_node,
                stream,
                pool,
                legacy_references,
                legacy_binary_references,
                limits,
            )?);
        }
    }
    Ok(group)
}

fn parse_entry(
    node: &XmlNode,
    stream: &mut InnerCipher,
    pool: &mut BinaryPool,
    legacy_references: &BTreeMap<u32, usize>,
    legacy_binary_references: bool,
    limits: &KdbxReadLimits,
) -> Result<Entry, KdbxError> {
    ensure_children_allowed(
        node,
        &[
            "UUID",
            "Name",
            "OverrideURL",
            "IconID",
            "CustomIconUUID",
            "ForegroundColor",
            "BackgroundColor",
            "QualityCheck",
            "PreviousParentGroup",
            "Tags",
            "Times",
            "String",
            "Binary",
            "AutoType",
            "CustomData",
            "History",
        ],
    )?;
    let mut entry = Entry::new(text(node, "Name").unwrap_or("Entry"));
    if let Some(value) = text(node, "UUID") {
        entry.id = KdbxUuid::from_base64(value)?;
    }
    if let Some(value) = text(node, "OverrideURL") {
        entry.url = value.into();
    }
    if let Some(value) = text(node, "IconID") {
        entry.icon_id = value
            .parse()
            .map_err(|_| KdbxError::malformed("invalid entry IconID"))?;
    }
    if let Some(value) = text(node, "CustomIconUUID") {
        entry.custom_icon_id = KdbxUuid::from_base64(value)?;
    }
    if let Some(value) = text(node, "ForegroundColor") {
        entry.foreground_color = KdbxColor::parse(value)?;
    }
    if let Some(value) = text(node, "BackgroundColor") {
        entry.background_color = KdbxColor::parse(value)?;
    }
    if let Some(value) = text(node, "QualityCheck") {
        entry.quality_check = Some(value == "True");
    }
    if let Some(value) = text(node, "PreviousParentGroup") {
        entry.previous_parent_group_id = KdbxUuid::from_base64(value)?;
    }
    if let Some(custom) = child(node, "CustomData") {
        entry.custom_data = parse_custom_data(custom, false)?;
    }
    if let Some(value) = text(node, "Tags") {
        entry.tags = value
            .split(';')
            .filter(|tag| !tag.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(times) = child(node, "Times") {
        entry.times = parse_times(times)?;
    }
    for string_node in children(node, "String") {
        let field = parse_field(string_node, stream)?;
        if let Ok(value) = field.value.reveal_text() {
            let value = value.as_str().to_owned();
            match field.key.as_str() {
                "UserName" => entry.username = value,
                "URL" => entry.url = value,
                "Password" => entry.password = field.value.clone(),
                _ => {}
            }
        }
        entry.set_field(field);
    }
    for binary_node in children(node, "Binary") {
        let name = required_text(binary_node, "Key")?;
        let value = child(binary_node, "Value")
            .ok_or_else(|| KdbxError::malformed("Binary is missing Value"))?;
        let reference = if let Some(reference) = value.attrs.get("Ref") {
            let id = reference
                .parse::<u32>()
                .map_err(|_| KdbxError::malformed("invalid Binary Ref"))?;
            if legacy_binary_references {
                *legacy_references.get(&id).ok_or_else(|| {
                    KdbxError::malformed("attachment references a missing legacy binary")
                })?
            } else {
                id as usize
            }
        } else {
            let data = decode_xml_binary(value, stream, limits)?;
            add_binary(pool, data, xml_bool(value, "Protected")?, limits)?
        };
        entry.attachments.push(Attachment { name, reference });
    }
    if let Some(auto) = child(node, "AutoType") {
        let associations = children(auto, "Association")
            .map(|association| AutoTypeAssociation {
                window: text(association, "Window").unwrap_or_default().into(),
                keystrokes: text(association, "KeystrokeSequence")
                    .or_else(|| text(association, "Keystrokes"))
                    .unwrap_or_default()
                    .into(),
            })
            .collect();
        let obfuscated = if let Some(value) = text(auto, "Obfuscated") {
            Some(value == "True" || value == "true" || value == "1")
        } else {
            text(auto, "DataTransferObfuscation").map(|value| value != "0")
        };
        entry.auto_type = AutoType {
            enabled: text(auto, "Enabled").map(|v| v == "True"),
            obfuscated,
            default_sequence: text(auto, "DefaultSequence").unwrap_or_default().into(),
            associations,
        };
    }
    if let Some(history) = child(node, "History") {
        for snapshot in children(history, "Entry") {
            entry.history.push(parse_entry(
                snapshot,
                stream,
                pool,
                legacy_references,
                legacy_binary_references,
                limits,
            )?);
        }
    }
    Ok(entry)
}

fn ensure_children_allowed(node: &XmlNode, allowed: &[&str]) -> Result<(), KdbxError> {
    if node.children.iter().any(|child| {
        !allowed.contains(&child.name.as_str())
            && child.attrs.iter().any(|(name, value)| {
                name == "Protected" && (value == "True" || value == "true" || value == "1")
            })
    }) {
        return Err(KdbxError::unsupported(
            "protected KDBX XML extension data is unsupported",
        ));
    }
    Ok(())
}

fn parse_field(node: &XmlNode, stream: &mut InnerCipher) -> Result<Field, KdbxError> {
    let key = required_text(node, "Key")?;
    let value =
        child(node, "Value").ok_or_else(|| KdbxError::malformed("String is missing Value"))?;
    let protected = xml_bool(value, "Protected")?;
    let protect_in_memory = xml_bool(value, "ProtectInMemory")?;
    let bytes = if protected {
        let mut bytes = STANDARD
            .decode(&value.text)
            .map_err(|_| KdbxError::malformed("invalid protected field Base64"))?;
        stream.transform(&mut bytes);
        bytes
    } else {
        value.text.as_bytes().to_vec()
    };
    let value = if protected {
        ProtectedValue::from_bytes_protected(bytes)?
    } else {
        ProtectedValue::from_bytes_unprotected(bytes)
    };
    Ok(Field {
        key,
        value,
        protected,
        protect_in_memory,
    })
}

fn parse_custom_data(node: &XmlNode, allow_timestamps: bool) -> Result<CustomData, KdbxError> {
    let mut data = CustomData::default();
    for item in children(node, "Item") {
        let key = required_text(item, "Key")?;
        let value = required_text(item, "Value")?;
        let last_modification = text(item, "LastModificationTime")
            .map(parse_timestamp)
            .transpose()?;
        if last_modification.is_some() && !allow_timestamps {
            return Err(KdbxError::unsupported(
                "timestamps on group or entry custom data are unsupported",
            ));
        }
        if data.get(&key).is_some() {
            return Err(KdbxError::malformed("duplicate KDBX custom-data key"));
        }
        data.set(key, value, last_modification);
    }
    Ok(data)
}

fn resolve_attachments(group: &Group, pool: &BinaryPool) -> Result<(), KdbxError> {
    fn entry_has_valid_attachments(entry: &Entry, pool: &BinaryPool) -> bool {
        entry
            .attachments
            .iter()
            .all(|attachment| pool.get(attachment.reference).is_some())
            && entry
                .history
                .iter()
                .all(|snapshot| entry_has_valid_attachments(snapshot, pool))
    }

    for entry in &group.entries {
        if !entry_has_valid_attachments(entry, pool) {
            return Err(KdbxError::malformed(
                "attachment references a missing binary",
            ));
        }
    }
    for child in &group.groups {
        resolve_attachments(child, pool)?;
    }
    Ok(())
}

pub(crate) fn write_inner_header(
    stream_id: u32,
    stream_key: &[u8],
    binaries: &[(Vec<u8>, bool)],
    stream: &mut InnerCipher,
) -> Vec<u8> {
    let mut output = Vec::new();
    write_field(&mut output, 1, &stream_id.to_le_bytes());
    write_field(&mut output, 2, stream_key);
    for (data, protected) in binaries {
        let mut value = Vec::with_capacity(data.len() + 1);
        value.push(u8::from(*protected));
        value.extend_from_slice(data);
        if *protected {
            stream.transform(&mut value[1..]);
        }
        write_field(&mut output, 3, &value);
    }
    write_field(&mut output, 0, &[]);
    output
}

fn write_field(output: &mut Vec<u8>, id: u8, value: &[u8]) {
    output.push(id);
    output.extend_from_slice(&(value.len() as i32).to_le_bytes());
    output.extend_from_slice(value);
}

/// Headless plaintext KeePass XML import/export helpers.
///
/// [`Debug`](std::fmt::Debug) is derived, and this is provably safe:
/// `KdbxXml` is a unit struct whose operations take the document as an
/// argument. The XML it produces and consumes is the caller's, and the
/// document model it borrows has its own redacting `Debug`, so this type
/// retains no plaintext for a derive to print.
#[derive(Debug)]
pub struct KdbxXml;

impl KdbxXml {
    /// Exports an unprotected KDBX XML document.
    ///
    /// # Errors
    ///
    /// Returns unsupported when protected fields or binaries require a KDBX
    /// inner stream.
    pub fn export(database: &KeePassDatabase) -> Result<Vec<u8>, KdbxError> {
        if !database.public_custom_data.items().is_empty()
            || !database.typed_public_custom_data.is_empty()
        {
            return Err(KdbxError::unsupported(
                "plain XML cannot represent public outer-header custom data",
            ));
        }
        if has_protected_values(database) {
            return Err(KdbxError::unsupported(
                "plain XML cannot represent protected values",
            ));
        }
        let mut stream = InnerCipher::new(2, &[0; 64])?;
        write_database(database, &mut stream, BinaryStorage::LegacyXml)
    }

    /// Imports an unprotected KDBX XML document.
    ///
    /// # Errors
    ///
    /// Returns malformed/unsupported errors for invalid XML or protected
    /// values, which require KDBX file context.
    pub fn import(data: &[u8], limits: &KdbxReadLimits) -> Result<KeePassDatabase, KdbxError> {
        std::str::from_utf8(data).map_err(|_| KdbxError::malformed("XML is not UTF-8"))?;
        let root = parse_tree(data, limits)?;
        if has_protected_payload(&root) {
            return Err(KdbxError::unsupported(
                "plain XML cannot import protected values",
            ));
        }
        let inner = InnerHeader {
            stream_id: 2,
            stream_key: vec![0; 64],
            binaries: Vec::new(),
            consumed: 0,
        };
        parse_database(data, &inner, &[], 0, true, None, limits)
    }
}

fn has_protected_values(database: &KeePassDatabase) -> bool {
    fn entry_has_protected(entry: &Entry) -> bool {
        !entry.password.is_empty()
            || entry.fields.iter().any(|field| field.protected)
            || entry.history.iter().any(entry_has_protected)
    }
    fn group_has_protected(group: &Group) -> bool {
        group.entries.iter().any(entry_has_protected)
            || group.groups.iter().any(group_has_protected)
    }

    group_has_protected(&database.root)
        || database
            .binary_pool
            .records()
            .iter()
            .any(|record| record.protected)
}

#[derive(Clone, Copy)]
pub(crate) enum BinaryStorage {
    InnerHeader,
    LegacyXml,
}

pub(crate) fn write_database(
    database: &KeePassDatabase,
    stream: &mut InnerCipher,
    storage: BinaryStorage,
) -> Result<Vec<u8>, KdbxError> {
    write_database_inner(database, stream, storage, None)
}

pub(crate) fn write_database_with_header_hash(
    database: &KeePassDatabase,
    stream: &mut InnerCipher,
    storage: BinaryStorage,
    header_hash: &[u8; 32],
) -> Result<Vec<u8>, KdbxError> {
    write_database_inner(database, stream, storage, Some(header_hash))
}

fn write_database_inner(
    database: &KeePassDatabase,
    stream: &mut InnerCipher,
    storage: BinaryStorage,
    header_hash: Option<&[u8; 32]>,
) -> Result<Vec<u8>, KdbxError> {
    if !database.can_save_losslessly {
        return Err(KdbxError::unsupported(
            "document cannot be saved losslessly",
        ));
    }
    if !legacy_binary_state_is_consistent(database) {
        return Err(KdbxError::unsupported(
            "legacy and inner binary pools disagree",
        ));
    }
    let binary_count = if database.binary_pool.is_empty() {
        database.meta.legacy_binaries.len()
    } else {
        database.binary_pool.len()
    };
    if !attachment_references_valid(&database.root, binary_count) {
        return Err(KdbxError::new(
            crate::KdbxFailureKind::InvalidArgument,
            "attachment references a missing binary",
        ));
    }
    if !tree_custom_data_is_xml_compatible(&database.root) {
        return Err(KdbxError::unsupported(
            "timestamps on group or entry custom data are unsupported",
        ));
    }
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><KeePassFile><Meta>");
    let generator = if database.meta.generator.is_empty() {
        "Neotales KeePass Rust"
    } else {
        &database.meta.generator
    };
    write_text(&mut xml, "Generator", generator);
    if let Some(header_hash) = header_hash {
        write_text(&mut xml, "HeaderHash", &STANDARD.encode(header_hash));
    }
    write_text(&mut xml, "DatabaseName", &database.meta.name);
    write_text(&mut xml, "DatabaseDescription", &database.meta.description);
    write_text(&mut xml, "DefaultUserName", &database.meta.default_username);
    if let Some(value) = database.meta.settings_changed {
        write_text(
            &mut xml,
            "SettingsChanged",
            &STANDARD.encode(value.0.to_le_bytes()),
        );
    }
    if let Some(value) = database.meta.database_name_changed {
        write_text(
            &mut xml,
            "DatabaseNameChanged",
            &STANDARD.encode(value.0.to_le_bytes()),
        );
    }
    if let Some(value) = database.meta.database_description_changed {
        write_text(
            &mut xml,
            "DatabaseDescriptionChanged",
            &STANDARD.encode(value.0.to_le_bytes()),
        );
    }
    if let Some(value) = database.meta.default_username_changed {
        write_text(
            &mut xml,
            "DefaultUserNameChanged",
            &STANDARD.encode(value.0.to_le_bytes()),
        );
    }
    if let Some(value) = database.meta.master_key_changed {
        write_text(
            &mut xml,
            "MasterKeyChanged",
            &STANDARD.encode(value.0.to_le_bytes()),
        );
    }
    write_text(
        &mut xml,
        "MaintenanceHistoryDays",
        &database.meta.maintenance_history_days.to_string(),
    );
    write_text(&mut xml, "Color", &database.meta.color.to_string());
    write_text(
        &mut xml,
        "MasterKeyChangeRec",
        &database.meta.master_key_change_rec.to_string(),
    );
    write_text(
        &mut xml,
        "MasterKeyChangeForce",
        &database.meta.master_key_change_force.to_string(),
    );
    write_text(
        &mut xml,
        "MasterKeyChangeForceOnce",
        if database.meta.master_key_change_force_once {
            "True"
        } else {
            "False"
        },
    );
    write_times(&mut xml, &database.meta.times);
    write_memory_protection(&mut xml, &database.meta);
    write_custom_icons(&mut xml, &database.meta.custom_icons);
    if let Some(value) = database.meta.history_max_items {
        write_text(&mut xml, "HistoryMaxItems", &value.to_string());
    }
    if let Some(value) = database.meta.history_max_size {
        write_text(&mut xml, "HistoryMaxSize", &value.to_string());
    }
    write_text(
        &mut xml,
        "RecycleBinEnabled",
        if database.meta.recycle_bin_enabled {
            "True"
        } else {
            "False"
        },
    );
    write_text(
        &mut xml,
        "RecycleBinUUID",
        &database.meta.recycle_bin_uuid.to_base64(),
    );
    if let Some(value) = database.meta.recycle_bin_changed {
        write_text(
            &mut xml,
            "RecycleBinChanged",
            &STANDARD.encode(value.0.to_le_bytes()),
        );
    }
    write_text(
        &mut xml,
        "EntryTemplatesGroup",
        &database.meta.templates_uuid.to_base64(),
    );
    if let Some(value) = database.meta.templates_changed {
        write_text(
            &mut xml,
            "EntryTemplatesGroupChanged",
            &STANDARD.encode(value.0.to_le_bytes()),
        );
    }
    write_text(
        &mut xml,
        "LastSelectedGroup",
        &database.meta.selected_group_uuid.to_base64(),
    );
    write_text(
        &mut xml,
        "LastTopVisibleGroup",
        &database.meta.top_visible_group_uuid.to_base64(),
    );
    write_custom_data(&mut xml, &database.meta.custom_data, true);
    if matches!(storage, BinaryStorage::LegacyXml) {
        write_legacy_binaries(&mut xml, database, stream)?;
    }
    xml.push_str("</Meta><Root>");
    write_group(&mut xml, &database.root, &mut *stream)?;
    if !database.deleted_objects.is_empty() {
        xml.push_str("<DeletedObjects>");
        for deleted in &database.deleted_objects {
            write!(
                xml,
                "<DeletedObject><UUID>{}</UUID><DeletionTime>{}</DeletionTime></DeletedObject>",
                deleted.id.to_base64(),
                STANDARD.encode(deleted.deleted_at.0.to_le_bytes())
            )
            .expect("writing to String cannot fail");
        }
        xml.push_str("</DeletedObjects>");
    }
    xml.push_str("</Root></KeePassFile>");
    Ok(xml.into_bytes())
}

fn write_memory_protection(xml: &mut String, meta: &KeePassMeta) {
    let has_settings = meta.protect_password
        || meta.protect_title
        || meta.protect_username
        || meta.protect_url
        || meta.protect_notes;
    if !meta.memory_protection && !has_settings {
        return;
    }
    xml.push_str("<MemoryProtection>");
    for (name, enabled) in [
        ("ProtectPassword", meta.protect_password),
        ("ProtectTitle", meta.protect_title),
        ("ProtectUsername", meta.protect_username),
        ("ProtectURL", meta.protect_url),
        ("ProtectNotes", meta.protect_notes),
    ] {
        write_text(xml, name, if enabled { "True" } else { "False" });
    }
    xml.push_str("</MemoryProtection>");
}

fn write_custom_icons(xml: &mut String, icons: &[CustomIcon]) {
    if icons.is_empty() {
        return;
    }
    xml.push_str("<CustomIcons>");
    for icon in icons {
        xml.push_str("<Icon>");
        write_text(xml, "UUID", &icon.uuid.to_base64());
        write_text(xml, "Data", &STANDARD.encode(&icon.data));
        if let Some(name) = &icon.name {
            write_text(xml, "Name", name);
        }
        if let Some(timestamp) = icon.last_modification {
            write_text(
                xml,
                "LastModificationTime",
                &STANDARD.encode(timestamp.0.to_le_bytes()),
            );
        }
        xml.push_str("</Icon>");
    }
    xml.push_str("</CustomIcons>");
}

fn tree_custom_data_is_xml_compatible(group: &Group) -> bool {
    fn entry_is_compatible(entry: &Entry) -> bool {
        entry
            .custom_data
            .items()
            .iter()
            .all(|item| item.last_modification.is_none())
            && entry.history.iter().all(entry_is_compatible)
    }
    group
        .custom_data
        .items()
        .iter()
        .all(|item| item.last_modification.is_none())
        && group.entries.iter().all(entry_is_compatible)
        && group
            .groups
            .iter()
            .all(|child| tree_custom_data_is_xml_compatible(child))
}

fn attachment_references_valid(group: &Group, binary_count: usize) -> bool {
    fn entry_valid(entry: &Entry, binary_count: usize) -> bool {
        entry
            .attachments
            .iter()
            .all(|attachment| attachment.reference < binary_count)
            && entry
                .history
                .iter()
                .all(|snapshot| entry_valid(snapshot, binary_count))
    }
    group
        .entries
        .iter()
        .all(|entry| entry_valid(entry, binary_count))
        && group
            .groups
            .iter()
            .all(|child| attachment_references_valid(child, binary_count))
}

fn legacy_binary_state_is_consistent(database: &KeePassDatabase) -> bool {
    database.meta.legacy_binaries.is_empty()
        || database.binary_pool.is_empty()
        || (database.binary_pool.len() == database.meta.legacy_binaries.len()
            && database
                .binary_pool
                .records()
                .iter()
                .zip(&database.meta.legacy_binaries)
                .all(|(record, legacy)| record.data == *legacy))
}

fn write_legacy_binaries(
    xml: &mut String,
    database: &KeePassDatabase,
    stream: &mut InnerCipher,
) -> Result<(), KdbxError> {
    if database.binary_pool.is_empty() && database.meta.legacy_binaries.is_empty() {
        return Ok(());
    }
    let binaries: Vec<(Vec<u8>, bool)> = if database.binary_pool.is_empty() {
        database
            .meta
            .legacy_binaries
            .iter()
            .map(|data| (data.clone(), false))
            .collect()
    } else {
        database
            .binary_pool
            .records()
            .iter()
            .map(|record| (record.data.clone(), record.protected))
            .collect()
    };
    if !attachment_references_valid(&database.root, binaries.len()) {
        return Err(KdbxError::new(
            crate::KdbxFailureKind::InvalidArgument,
            "attachment references a missing binary",
        ));
    }
    xml.push_str("<Binaries>");
    for (id, (data, protected)) in binaries.into_iter().enumerate() {
        let mut data = data;
        if protected {
            stream.transform(&mut data);
        }
        write!(
            xml,
            "<Binary ID=\"{}\" Compressed=\"False\"{}>{}</Binary>",
            id,
            if protected { " Protected=\"True\"" } else { "" },
            STANDARD.encode(&data)
        )
        .expect("writing to String cannot fail");
        data.zeroize();
    }
    xml.push_str("</Binaries>");
    Ok(())
}

fn write_group(xml: &mut String, group: &Group, stream: &mut InnerCipher) -> Result<(), KdbxError> {
    xml.push_str("<Group>");
    write_text(xml, "UUID", &group.id.to_base64());
    write_text(xml, "Name", &group.name);
    write_text(xml, "Notes", &group.notes);
    write_text(xml, "IconID", &group.icon_id.to_string());
    if !group.custom_icon_id.is_zero() {
        write_text(xml, "CustomIconUUID", &group.custom_icon_id.to_base64());
    }
    write_text(
        xml,
        "IsExpanded",
        if group.is_expanded { "True" } else { "False" },
    );
    write_text(
        xml,
        "DefaultAutoTypeSequence",
        &group.default_auto_type_sequence,
    );
    if let Some(value) = group.enable_auto_type {
        write_text(xml, "EnableAutoType", if value { "True" } else { "False" });
    }
    if let Some(value) = group.enable_searching {
        write_text(xml, "EnableSearching", if value { "True" } else { "False" });
    }
    write_text(
        xml,
        "LastTopVisibleEntry",
        &group.last_top_visible_entry_id.to_base64(),
    );
    write_text(
        xml,
        "PreviousParentGroup",
        &group.previous_parent_group_id.to_base64(),
    );
    write_times(xml, &group.times);
    if !group.tags.is_empty() {
        write_text(xml, "Tags", &group.tags.join(";"));
    }
    write_custom_data(xml, &group.custom_data, false);
    for entry in &group.entries {
        write_entry(xml, entry, stream)?;
    }
    for child in &group.groups {
        write_group(xml, child, stream)?;
    }
    xml.push_str("</Group>");
    Ok(())
}
fn write_entry(xml: &mut String, entry: &Entry, stream: &mut InnerCipher) -> Result<(), KdbxError> {
    xml.push_str("<Entry>");
    write_text(xml, "UUID", &entry.id.to_base64());
    write_text(xml, "Name", &entry.title);
    write_text(xml, "OverrideURL", &entry.url);
    write_text(xml, "IconID", &entry.icon_id.to_string());
    if !entry.custom_icon_id.is_zero() {
        write_text(xml, "CustomIconUUID", &entry.custom_icon_id.to_base64());
    }
    write_text(xml, "ForegroundColor", &entry.foreground_color.to_string());
    write_text(xml, "BackgroundColor", &entry.background_color.to_string());
    if let Some(value) = entry.quality_check {
        write_text(xml, "QualityCheck", if value { "True" } else { "False" });
    }
    write_text(
        xml,
        "PreviousParentGroup",
        &entry.previous_parent_group_id.to_base64(),
    );
    write_times(xml, &entry.times);
    if !entry.username.is_empty() && entry.field("UserName").is_none() {
        write_field_xml(
            xml,
            "UserName",
            entry.username.as_bytes(),
            false,
            false,
            stream,
        )?;
    }
    if !entry.url.is_empty() && entry.field("URL").is_none() {
        write_field_xml(xml, "URL", entry.url.as_bytes(), false, false, stream)?;
    }
    if !entry.password.is_empty() && entry.field("Password").is_none() {
        entry.password.with_revealed_bytes(|password| {
            write_field_xml(xml, "Password", password, true, false, stream)
        })??;
    }
    for field in &entry.fields {
        xml.push_str("<String>");
        write_text(xml, "Key", &field.key);
        if field.protected {
            let encoded = field.value.with_revealed_bytes(|bytes| {
                stream.transform(bytes);
                STANDARD.encode(bytes)
            })?;
            write!(
                xml,
                "<Value Protected=\"True\" ProtectInMemory=\"{}\">{}</Value>",
                field.protect_in_memory, encoded
            )
            .expect("writing to String cannot fail");
        } else {
            let text = field.value.reveal_text()?.as_str().to_owned();
            write!(xml, "<Value>{}</Value>", escape(&text)).expect("writing to String cannot fail");
        }
        xml.push_str("</String>");
    }
    for attachment in &entry.attachments {
        write!(
            xml,
            "<Binary><Key>{}</Key><Value Ref=\"{}\"/></Binary>",
            escape(&attachment.name),
            attachment.reference
        )
        .expect("writing to String cannot fail");
    }
    if entry.auto_type.enabled.is_some()
        || entry.auto_type.obfuscated.is_some()
        || !entry.auto_type.default_sequence.is_empty()
        || !entry.auto_type.associations.is_empty()
    {
        xml.push_str("<AutoType>");
        if let Some(enabled) = entry.auto_type.enabled {
            write_text(xml, "Enabled", if enabled { "True" } else { "False" });
        }
        if let Some(obfuscated) = entry.auto_type.obfuscated {
            write_text(
                xml,
                "DataTransferObfuscation",
                if obfuscated { "1" } else { "0" },
            );
        }
        if !entry.auto_type.default_sequence.is_empty() {
            write_text(xml, "DefaultSequence", &entry.auto_type.default_sequence);
        }
        for association in &entry.auto_type.associations {
            write!(
                xml,
                "<Association><Window>{}</Window><KeystrokeSequence>{}</KeystrokeSequence></Association>",
                escape(&association.window),
                escape(&association.keystrokes)
            )
            .expect("writing to String cannot fail");
        }
        xml.push_str("</AutoType>");
    }
    write_custom_data(xml, &entry.custom_data, false);
    if !entry.history.is_empty() {
        xml.push_str("<History>");
        for snapshot in &entry.history {
            write_entry(xml, snapshot, stream)?;
        }
        xml.push_str("</History>");
    }
    xml.push_str("</Entry>");
    Ok(())
}
fn write_field_xml(
    xml: &mut String,
    key: &str,
    value: &[u8],
    protected: bool,
    protect_in_memory: bool,
    stream: &mut InnerCipher,
) -> Result<(), KdbxError> {
    xml.push_str("<String>");
    write_text(xml, "Key", key);
    if protected {
        let mut bytes = value.to_vec();
        stream.transform(&mut bytes);
        write!(
            xml,
            "<Value Protected=\"True\" ProtectInMemory=\"{}\">{}</Value>",
            protect_in_memory,
            STANDARD.encode(&bytes)
        )
        .expect("writing to String cannot fail");
        bytes.zeroize();
    } else {
        let text = std::str::from_utf8(value)
            .map_err(|_| KdbxError::malformed("unprotected KDBX field is not UTF-8"))?;
        write!(xml, "<Value>{}</Value>", escape(text)).expect("writing to String cannot fail");
    }
    xml.push_str("</String>");
    Ok(())
}

fn write_custom_data(xml: &mut String, data: &CustomData, write_timestamps: bool) {
    if data.items().is_empty() {
        return;
    }
    xml.push_str("<CustomData>");
    for item in data.items() {
        write!(
            xml,
            "<Item><Key>{}</Key><Value>{}</Value>",
            escape(&item.key),
            escape(&item.value)
        )
        .expect("writing to String cannot fail");
        if let Some(timestamp) = item.last_modification.filter(|_| write_timestamps) {
            write_text(
                xml,
                "LastModificationTime",
                &STANDARD.encode(timestamp.0.to_le_bytes()),
            );
        }
        xml.push_str("</Item>");
    }
    xml.push_str("</CustomData>");
}

fn write_times(xml: &mut String, times: &KeePassTimes) {
    xml.push_str("<Times>");
    for (name, value) in [
        ("CreationTime", times.created),
        ("LastModificationTime", times.modified),
        ("LastAccessTime", times.accessed),
        ("ExpiryTime", times.expires),
        ("LocationChanged", times.location_changed),
    ] {
        write_text(xml, name, &STANDARD.encode(value.0.to_le_bytes()));
    }
    write_text(
        xml,
        "Expires",
        if times.expires_enabled {
            "True"
        } else {
            "False"
        },
    );
    write_text(xml, "UsageCount", &times.usage_count.to_string());
    xml.push_str("</Times>");
}
fn write_text(xml: &mut String, name: &str, value: &str) {
    write!(xml, "<{name}>{}</{name}>", escape(value)).expect("writing to String cannot fail");
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
