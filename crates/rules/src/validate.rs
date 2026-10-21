//! Strict manifest validation (TRD §8.2). Every structural rule is enforced here so that a
//! malformed manifest can never produce a binary with a silently reduced rule set.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde_json::{Map, Value};

use crate::{
    Charset, Compiled, Detector, Format, ManifestError, Rule, RuleData, Segment, sha256_hex,
};

type Obj = Map<String, Value>;

pub(crate) fn compile(bytes: &[u8]) -> Result<Compiled, ManifestError> {
    let root: Value =
        serde_json::from_slice(bytes).map_err(|e| ManifestError::Json(e.to_string()))?;
    let root = root
        .as_object()
        .ok_or_else(|| ManifestError::InvalidField("$".into()))?;

    let schema_version = req_u64(root, "schemaVersion", "$")?;
    if schema_version != 1 {
        return Err(ManifestError::UnsupportedSchemaVersion(schema_version));
    }

    let rule_version = req_str(root, "ruleVersion", "$")?.to_owned();
    if !is_semver(&rule_version) {
        return Err(ManifestError::InvalidRuleVersion(rule_version));
    }

    let placeholders = str_list(root, "placeholders", "$")?;
    let mut seen = BTreeSet::new();
    for p in &placeholders {
        let inner = p.strip_prefix('[').and_then(|s| s.strip_suffix(']'));
        let ok = inner.is_some_and(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_uppercase() || b == b' ')
        });
        if !ok || !seen.insert(p.clone()) {
            return Err(ManifestError::InvalidPlaceholder(p.clone()));
        }
    }
    if placeholders.is_empty() {
        return Err(ManifestError::MissingField("$.placeholders".into()));
    }

    let rules_v = root
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| ManifestError::MissingField("$.rules".into()))?;

    // Identity checks first so duplicate ids are reported as such.
    let mut ids = Vec::with_capacity(rules_v.len());
    for (i, r) in rules_v.iter().enumerate() {
        let obj = r
            .as_object()
            .ok_or_else(|| ManifestError::InvalidField(format!("$.rules[{i}]")))?;
        let id = req_str(obj, "id", &format!("$.rules[{i}]"))?.to_owned();
        if !is_rule_id(&id) {
            return Err(ManifestError::InvalidId(id));
        }
        if ids.contains(&id) {
            return Err(ManifestError::DuplicateId(id));
        }
        ids.push(id);
    }
    if ids.windows(2).any(|w| w[0] >= w[1]) {
        return Err(ManifestError::IdsNotAscending);
    }

    // Detector identity next: unknown, duplicated, or missing detectors are reported before any
    // detector-specific validation, which depends on knowing the detector.
    let mut detectors_seen = Vec::new();
    for (i, r) in rules_v.iter().enumerate() {
        let path = format!("$.rules[{i}]");
        let obj = r
            .as_object()
            .ok_or_else(|| ManifestError::InvalidField(path.clone()))?;
        let name = req_str(obj, "detector", &path)?;
        let det = Detector::from_manifest_name(name)
            .ok_or_else(|| ManifestError::UnknownDetector(name.into()))?;
        if detectors_seen.contains(&det) {
            return Err(ManifestError::DuplicateDetector(name.into()));
        }
        detectors_seen.push(det);
    }
    for d in Detector::ALL {
        if !detectors_seen.contains(&d) {
            return Err(ManifestError::MissingDetector(d.manifest_name().into()));
        }
    }

    let mut rules = Vec::with_capacity(rules_v.len());
    for (i, r) in rules_v.iter().enumerate() {
        let path = format!("$.rules[{i}]");
        let obj = r
            .as_object()
            .ok_or_else(|| ManifestError::InvalidField(path.clone()))?;
        rules.push(parse_rule(obj, &path, &placeholders)?);
    }

    let precedence = str_list(root, "precedence", "$")?;
    let mut sorted_prec = precedence.clone();
    sorted_prec.sort();
    let mut sorted_ids = ids.clone();
    sorted_ids.sort();
    if sorted_prec != sorted_ids {
        return Err(ManifestError::PrecedenceMismatch);
    }

    Ok(Compiled {
        schema_version: 1,
        rule_version,
        sha256_hex: sha256_hex(bytes),
        placeholders,
        precedence,
        rules,
    })
}

fn parse_rule(obj: &Obj, path: &str, placeholders: &[String]) -> Result<Rule, ManifestError> {
    let id = req_str(obj, "id", path)?.to_owned();
    let name = req_str(obj, "name", path)?.to_owned();
    let det_name = req_str(obj, "detector", path)?;
    let detector = Detector::from_manifest_name(det_name)
        .ok_or_else(|| ManifestError::UnknownDetector(det_name.into()))?;
    let default_enabled = req_bool(obj, "defaultEnabled", path)?;
    let optional = req_bool(obj, "optional", path)?;
    let must_be_optional = matches!(detector, Detector::Email | Detector::PrivateIp);
    if optional != must_be_optional || (!optional && !default_enabled) {
        return Err(ManifestError::OptionalMismatch(id));
    }
    let placeholder = req_str(obj, "placeholder", path)?.to_owned();
    if !placeholders.contains(&placeholder) {
        return Err(ManifestError::PlaceholderNotReserved(placeholder));
    }
    let description = req_str(obj, "description", path)?.to_owned();

    let mut examples = Vec::new();
    for (i, ex) in req_array(obj, "examples", path)?.iter().enumerate() {
        let pair = ex.as_array().filter(|a| a.len() == 2);
        let (a, b) = match pair.map(|a| (a[0].as_str(), a[1].as_str())) {
            Some((Some(a), Some(b))) => (a.to_owned(), b.to_owned()),
            _ => return Err(ManifestError::InvalidField(format!("{path}.examples[{i}]"))),
        };
        examples.push((a, b));
    }
    let non_examples = str_list(obj, "nonExamples", path)?;
    let limitations = str_list(obj, "limitations", path)?;

    let data_path = format!("{path}.data");
    let data_obj = obj
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| ManifestError::MissingField(data_path.clone()))?;
    let data = parse_data(detector, data_obj, &data_path)?;

    Ok(Rule {
        id,
        name,
        detector,
        default_enabled,
        optional,
        placeholder,
        description,
        examples,
        non_examples,
        limitations,
        data,
    })
}

fn parse_data(detector: Detector, obj: &Obj, path: &str) -> Result<RuleData, ManifestError> {
    let mut d = RuleData::default();
    match detector {
        Detector::NamedValue => {
            d.single_aliases = str_list(obj, "singleAliases", path)?;
            for a in &d.single_aliases {
                check_alias(a)?;
            }
            for (i, p) in req_array(obj, "pairAliases", path)?.iter().enumerate() {
                let pair = p.as_array().filter(|a| a.len() == 2);
                let (a, b) = match pair.map(|a| (a[0].as_str(), a[1].as_str())) {
                    Some((Some(a), Some(b))) => (a.to_owned(), b.to_owned()),
                    _ => {
                        return Err(ManifestError::InvalidField(format!(
                            "{path}.pairAliases[{i}]"
                        )));
                    }
                };
                check_alias(&a)?;
                check_alias(&b)?;
                d.pair_aliases.push((a, b));
            }
            d.skip_values = str_list(obj, "skipValues", path)?;
            if d.skip_values
                .iter()
                .any(|v| v.is_empty() || v.bytes().any(|b| !b.is_ascii_graphic()))
            {
                return Err(ManifestError::InvalidField(format!("{path}.skipValues")));
            }
        }
        Detector::Authorization => {
            d.headers = str_list(obj, "headers", path)?;
            check_headers(&d.headers)?;
            d.schemes = str_list(obj, "schemes", path)?;
            let ok = !d.schemes.is_empty()
                && d.schemes.iter().all(|s| {
                    !s.is_empty()
                        && s.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                });
            if !ok {
                return Err(ManifestError::InvalidField(format!("{path}.schemes")));
            }
        }
        Detector::Cookie => {
            d.request_headers = str_list(obj, "requestHeaders", path)?;
            d.response_headers = str_list(obj, "responseHeaders", path)?;
            check_headers(&d.request_headers)?;
            check_headers(&d.response_headers)?;
        }
        Detector::HomePath => {
            d.posix_prefixes = str_list(obj, "posixPrefixes", path)?;
            let ok = d.posix_prefixes.iter().all(|p| {
                p.len() >= 3
                    && p.starts_with('/')
                    && p.ends_with('/')
                    && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'/')
            });
            if !ok || d.posix_prefixes.is_empty() {
                return Err(ManifestError::InvalidField(format!("{path}.posixPrefixes")));
            }
            d.windows_directory = req_str(obj, "windowsDirectory", path)?.to_owned();
            if d.windows_directory.is_empty()
                || !d.windows_directory.bytes().all(|b| b.is_ascii_lowercase())
            {
                return Err(ManifestError::InvalidField(format!(
                    "{path}.windowsDirectory"
                )));
            }
        }
        Detector::PrivateIp => {
            for c in str_list(obj, "ipv4", path)? {
                d.ipv4
                    .push(parse_cidr4(&c).ok_or(ManifestError::InvalidCidr(c))?);
            }
            for c in str_list(obj, "ipv6", path)? {
                d.ipv6
                    .push(parse_cidr6(&c).ok_or(ManifestError::InvalidCidr(c))?);
            }
            if d.ipv4.is_empty() && d.ipv6.is_empty() {
                return Err(ManifestError::MissingField(format!("{path}.ipv4")));
            }
        }
        Detector::TokenFormat => {
            let mut ids = BTreeSet::new();
            for (i, f) in req_array(obj, "formats", path)?.iter().enumerate() {
                let fpath = format!("{path}.formats[{i}]");
                let fobj = f
                    .as_object()
                    .ok_or_else(|| ManifestError::InvalidField(fpath.clone()))?;
                let fmt = parse_format(fobj, &fpath)?;
                if !ids.insert(fmt.id.clone()) {
                    return Err(ManifestError::InvalidFormat(format!(
                        "duplicate format id {}",
                        fmt.id
                    )));
                }
                d.formats.push(fmt);
            }
            if d.formats.is_empty() {
                return Err(ManifestError::MissingField(format!("{path}.formats")));
            }
        }
        Detector::PemBlock => {
            d.label_suffixes = str_list(obj, "labelSuffixes", path)?;
            let ok = !d.label_suffixes.is_empty()
                && d.label_suffixes.iter().all(|s| {
                    !s.is_empty() && s.bytes().all(|b| b.is_ascii_uppercase() || b == b' ')
                });
            if !ok {
                return Err(ManifestError::InvalidField(format!("{path}.labelSuffixes")));
            }
            let max = req_u64(obj, "maxLabelPrefix", path)?;
            d.max_label_prefix = u32::try_from(max)
                .ok()
                .filter(|m| *m <= 64)
                .ok_or_else(|| ManifestError::InvalidField(format!("{path}.maxLabelPrefix")))?;
        }
        Detector::UrlCredential | Detector::Email => {}
    }
    Ok(d)
}

fn parse_format(obj: &Obj, path: &str) -> Result<Format, ManifestError> {
    let id = req_str(obj, "id", path)?.to_owned();
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(ManifestError::InvalidFormat(format!("bad id {id:?}")));
    }
    let source = match obj.get("source") {
        None => return Err(ManifestError::FormatWithoutSource(id)),
        Some(v) => v.as_str().unwrap_or_default().to_owned(),
    };
    if !source.starts_with("https://") {
        return Err(ManifestError::InvalidFormat(format!(
            "{id}: source must be an https URL"
        )));
    }
    let provider = req_str(obj, "provider", path)?.to_owned();
    let prefixes = str_list(obj, "prefixes", path)?;
    if prefixes.is_empty()
        || prefixes
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_graphic()))
    {
        return Err(ManifestError::InvalidFormat(format!("{id}: prefixes")));
    }
    let mut segments = Vec::new();
    for (i, s) in req_array(obj, "segments", path)?.iter().enumerate() {
        let spath = format!("{path}.segments[{i}]");
        let sobj = s
            .as_object()
            .ok_or_else(|| ManifestError::InvalidField(spath.clone()))?;
        let cs_name = req_str(sobj, "charset", &spath)?;
        let charset = Charset::from_manifest_name(cs_name).ok_or_else(|| {
            ManifestError::InvalidFormat(format!("{id}: unknown charset {cs_name:?}"))
        })?;
        let min = u32::try_from(req_u64(sobj, "min", &spath)?)
            .ok()
            .filter(|m| *m <= 1024)
            .ok_or_else(|| ManifestError::InvalidFormat(format!("{id}: min out of range")))?;
        let exact = match sobj.get("exact") {
            None => false,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| ManifestError::InvalidField(format!("{spath}.exact")))?,
        };
        if exact && min == 0 {
            return Err(ManifestError::InvalidFormat(format!(
                "{id}: exact segment needs min > 0"
            )));
        }
        segments.push(Segment {
            charset,
            min,
            exact,
        });
    }
    if segments.is_empty() || segments.first().is_some_and(|s| s.min == 0) {
        return Err(ManifestError::InvalidFormat(format!(
            "{id}: first segment must be non-empty"
        )));
    }
    Ok(Format {
        id,
        provider,
        prefixes,
        segments,
        source,
    })
}

fn check_alias(a: &str) -> Result<(), ManifestError> {
    if a.is_empty()
        || !a
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(ManifestError::InvalidAlias(a.to_owned()));
    }
    Ok(())
}

fn check_headers(h: &[String]) -> Result<(), ManifestError> {
    if h.is_empty() {
        return Err(ManifestError::InvalidHeader(String::new()));
    }
    for name in h {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
            return Err(ManifestError::InvalidHeader(name.clone()));
        }
    }
    Ok(())
}

fn parse_cidr4(s: &str) -> Option<(u32, u8)> {
    let (addr, len) = s.split_once('/')?;
    let addr: Ipv4Addr = addr.parse().ok()?;
    let len: u8 = len.parse().ok().filter(|l| *l <= 32)?;
    let net = u32::from(addr);
    let host_mask = if len == 0 { u32::MAX } else { u32::MAX >> len };
    (net & host_mask == 0 || len == 32).then_some((net, len))
}

fn parse_cidr6(s: &str) -> Option<(u128, u8)> {
    let (addr, len) = s.split_once('/')?;
    let addr: Ipv6Addr = addr.parse().ok()?;
    let len: u8 = len.parse().ok().filter(|l| *l <= 128)?;
    let net = u128::from(addr);
    let host_mask = if len == 0 {
        u128::MAX
    } else {
        u128::MAX >> len
    };
    (net & host_mask == 0 || len == 128).then_some((net, len))
}

fn is_semver(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

fn is_rule_id(id: &str) -> bool {
    id.len() == 6 && id.starts_with("SR-") && id[3..].bytes().all(|b| b.is_ascii_digit())
}

fn req<'a>(obj: &'a Obj, key: &str, path: &str) -> Result<&'a Value, ManifestError> {
    obj.get(key)
        .ok_or_else(|| ManifestError::MissingField(format!("{path}.{key}")))
}

fn req_str<'a>(obj: &'a Obj, key: &str, path: &str) -> Result<&'a str, ManifestError> {
    req(obj, key, path)?
        .as_str()
        .ok_or_else(|| ManifestError::InvalidField(format!("{path}.{key}")))
}

fn req_bool(obj: &Obj, key: &str, path: &str) -> Result<bool, ManifestError> {
    req(obj, key, path)?
        .as_bool()
        .ok_or_else(|| ManifestError::InvalidField(format!("{path}.{key}")))
}

fn req_u64(obj: &Obj, key: &str, path: &str) -> Result<u64, ManifestError> {
    req(obj, key, path)?
        .as_u64()
        .ok_or_else(|| ManifestError::InvalidField(format!("{path}.{key}")))
}

fn req_array<'a>(obj: &'a Obj, key: &str, path: &str) -> Result<&'a Vec<Value>, ManifestError> {
    req(obj, key, path)?
        .as_array()
        .ok_or_else(|| ManifestError::InvalidField(format!("{path}.{key}")))
}

fn str_list(obj: &Obj, key: &str, path: &str) -> Result<Vec<String>, ManifestError> {
    req_array(obj, key, path)?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| ManifestError::InvalidField(format!("{path}.{key}[{i}]")))
        })
        .collect()
}
