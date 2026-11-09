//! Bounded JSON parsing with decoded duplicate-member detection.
//!
//! This parser uses a Unicode-scalar string profile so decoded values fit Rust
//! strings. RFC 8259's grammar permits unpaired surrogate escapes, while its
//! parser guidance permits character-content limits; rejecting those escapes is
//! a representation limit, not an added CVD Policy conformance requirement.

use serde_json::{Map, Number, Value};

use crate::types::{Diagnostic, PolicyError, PolicyErrorKind};

const DEFAULT_MAX_BYTES: usize = 1_048_576;
const DEFAULT_MAX_DEPTH: usize = 64;
const DEFAULT_MAX_NODES: usize = 100_000;
const MAX_NUMBER_LEXEME_BYTES: usize = 4_096;
// Deep Value trees can recurse during downstream serialization and destruction.
const MAX_SAFE_NESTING_DEPTH: usize = 256;

/// Limits applied while parsing or checking an in-memory JSON value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    /// Maximum input bytes, or compact JSON bytes for an in-memory value.
    pub max_bytes: usize,
    /// Maximum nested container depth; values above 256 are clamped to 256.
    pub max_depth: usize,
    /// Maximum JSON values plus object member names.
    pub max_nodes: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_nodes: DEFAULT_MAX_NODES,
        }
    }
}

/// Parses exactly one UTF-8 JSON value and rejects duplicate object members.
///
/// A bounded tokenizer builds objects directly, so arbitrary-precision JSON
/// numbers cannot reinterpret a property named `$serde_json::private::Number`.
///
/// # Errors
///
/// Returns `PolicyErrorKind::Invalid` for malformed JSON or duplicate members,
/// and `PolicyErrorKind::ResourceLimit` when a configured bound is exceeded.
/// Unpaired UTF-16 surrogate escapes are rejected with
/// `policy_string_non_scalar`; paired escapes are decoded normally. This is a
/// Rust-string representation limit, not a new normative policy rule. Number
/// lexemes longer than 4,096 bytes are resource-limit failures, bounding exact
/// exponent arithmetic without constructing powers of ten.
///
/// # Examples
///
/// ```
/// use cvd_policy::{parse_json, ParseLimits};
///
/// let value = parse_json(br#"{"cvd_policy":1}"#, ParseLimits::default())?;
/// assert_eq!(value["cvd_policy"], 1);
/// # Ok::<(), cvd_policy::PolicyError>(())
/// ```
pub fn parse_json(raw: &[u8], limits: ParseLimits) -> Result<Value, PolicyError> {
    if raw.len() > limits.max_bytes {
        return Err(resource_error("JSON input exceeds the byte limit", None));
    }

    let input = std::str::from_utf8(raw)
        .map_err(|_| invalid_error("policy_parse_error", "JSON input is not valid UTF-8", 0))?;
    let mut parser = JsonParser {
        bytes: input.as_bytes(),
        position: 0,
        nodes: 0,
        limits,
    };

    parser.skip_whitespace();
    let mut stack = Vec::new();
    let mut root = None;

    while root.is_none() || !stack.is_empty() {
        if stack.is_empty() {
            parser.parse_value(&mut stack, &mut root)?;
            continue;
        }

        parser.skip_whitespace();
        let state = stack
            .last()
            .map(Frame::state)
            .ok_or_else(|| parser.invalid("invalid JSON parser state"))?;

        match state {
            FrameState::ArrayValueOrEnd if parser.peek() == Some(b']') => {
                parser.position += 1;
                parser.close_frame(&mut stack, &mut root)?;
            }
            FrameState::ArrayValueOrEnd | FrameState::ArrayValue => {
                if state == FrameState::ArrayValue && parser.peek() == Some(b']') {
                    return Err(parser.invalid("trailing comma in JSON array"));
                }
                parser.set_state(FrameState::ArraySeparator, &mut stack)?;
                parser.parse_value(&mut stack, &mut root)?;
            }
            FrameState::ArraySeparator => match parser.peek() {
                Some(b',') => {
                    parser.position += 1;
                    parser.set_state(FrameState::ArrayValue, &mut stack)?;
                }
                Some(b']') => {
                    parser.position += 1;
                    parser.close_frame(&mut stack, &mut root)?;
                }
                _ => return Err(parser.invalid("expected ',' or ']' in JSON array")),
            },
            FrameState::ObjectKeyOrEnd if parser.peek() == Some(b'}') => {
                parser.position += 1;
                parser.close_frame(&mut stack, &mut root)?;
            }
            FrameState::ObjectKeyOrEnd | FrameState::ObjectKey => {
                if state == FrameState::ObjectKey && parser.peek() == Some(b'}') {
                    return Err(parser.invalid("trailing comma in JSON object"));
                }
                let key = parser.parse_string()?;
                parser.count_node()?;
                let Some(Frame::Object { values, .. }) = stack.last() else {
                    return Err(parser.invalid("JSON object parser state is invalid"));
                };
                if values.contains_key(&key) {
                    return Err(duplicate_member_error(&key, parser.position));
                }
                parser.set_pending_key(key, &mut stack)?;
                parser.set_state(FrameState::ObjectColon, &mut stack)?;
            }
            FrameState::ObjectColon => {
                if parser.peek() != Some(b':') {
                    return Err(parser.invalid("expected ':' after JSON object member name"));
                }
                parser.position += 1;
                parser.set_state(FrameState::ObjectValue, &mut stack)?;
            }
            FrameState::ObjectValue => {
                parser.set_state(FrameState::ObjectSeparator, &mut stack)?;
                parser.parse_value(&mut stack, &mut root)?;
            }
            FrameState::ObjectSeparator => match parser.peek() {
                Some(b',') => {
                    parser.position += 1;
                    parser.set_state(FrameState::ObjectKey, &mut stack)?;
                }
                Some(b'}') => {
                    parser.position += 1;
                    parser.close_frame(&mut stack, &mut root)?;
                }
                _ => return Err(parser.invalid("expected ',' or '}' in JSON object")),
            },
        }
    }

    parser.skip_whitespace();
    if parser.position != parser.bytes.len() {
        return Err(parser.invalid("JSON input contains more than one value"));
    }

    root.ok_or_else(|| parser.invalid("JSON input is empty"))
}

/// Checks resource bounds on a caller-created value without recursion or cloning.
pub(crate) fn check_value_limits(value: &Value, limits: ParseLimits) -> Result<(), PolicyError> {
    let depth_limit = limits.max_depth.min(MAX_SAFE_NESTING_DEPTH);
    let mut pending = vec![(value, 0_usize)];
    let mut nodes = 0_usize;
    let mut json_bytes = 0_usize;

    while let Some((current, parent_depth)) = pending.pop() {
        count_checked_node(&mut nodes, limits.max_nodes)?;
        match current {
            Value::Null => add_checked_size(&mut json_bytes, 4, limits.max_bytes)?,
            Value::Bool(true) => add_checked_size(&mut json_bytes, 4, limits.max_bytes)?,
            Value::Bool(false) => add_checked_size(&mut json_bytes, 5, limits.max_bytes)?,
            Value::Number(number) => {
                let lexeme = number.as_str();
                if lexeme.len() > MAX_NUMBER_LEXEME_BYTES {
                    return Err(resource_error(
                        "JSON number lexeme exceeds the byte limit",
                        None,
                    ));
                }
                let bytes = lexeme.as_bytes();
                let starts_with_number = bytes
                    .first()
                    .is_some_and(|byte| *byte == b'-' || byte.is_ascii_digit());
                let ends_with_digit = bytes.last().is_some_and(|byte| byte.is_ascii_digit());
                // Exclude serde_json's private map encoding and outer JSON whitespace.
                if !starts_with_number
                    || !ends_with_digit
                    || serde_json::from_str::<Number>(lexeme).is_err()
                {
                    return Err(PolicyError::new(
                        PolicyErrorKind::Invalid,
                        vec![Diagnostic {
                            code: "policy_parse_error".to_owned(),
                            path: String::new(),
                            message: "caller-created JSON value contains an invalid number"
                                .to_owned(),
                        }],
                    ));
                }
                add_checked_size(&mut json_bytes, lexeme.len(), limits.max_bytes)?;
            }
            Value::String(string) => {
                add_checked_size(
                    &mut json_bytes,
                    encoded_string_len(string)
                        .ok_or_else(|| resource_error("JSON value exceeds the byte limit", None))?,
                    limits.max_bytes,
                )?;
            }
            Value::Array(values) => {
                let depth = parent_depth.saturating_add(1);
                check_depth(depth, depth_limit)?;
                add_checked_size(
                    &mut json_bytes,
                    2_usize.saturating_add(values.len().saturating_sub(1)),
                    limits.max_bytes,
                )?;
                pending.extend(values.iter().map(|child| (child, depth)));
            }
            Value::Object(values) => {
                let depth = parent_depth.saturating_add(1);
                check_depth(depth, depth_limit)?;
                add_checked_size(
                    &mut json_bytes,
                    2_usize.saturating_add(values.len().saturating_sub(1)),
                    limits.max_bytes,
                )?;
                for (key, child) in values {
                    count_checked_node(&mut nodes, limits.max_nodes)?;
                    add_checked_size(
                        &mut json_bytes,
                        encoded_string_len(key)
                            .and_then(|size| size.checked_add(1))
                            .ok_or_else(|| {
                                resource_error("JSON value exceeds the byte limit", None)
                            })?,
                        limits.max_bytes,
                    )?;
                    pending.push((child, depth));
                }
            }
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameState {
    ArrayValueOrEnd,
    ArrayValue,
    ArraySeparator,
    ObjectKeyOrEnd,
    ObjectKey,
    ObjectColon,
    ObjectValue,
    ObjectSeparator,
}

enum Frame {
    Array {
        values: Vec<Value>,
        state: FrameState,
    },
    Object {
        values: Map<String, Value>,
        state: FrameState,
        pending_key: Option<String>,
    },
}

impl Frame {
    fn state(&self) -> FrameState {
        match self {
            Self::Array { state, .. } | Self::Object { state, .. } => *state,
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
    nodes: usize,
    limits: ParseLimits,
}

impl JsonParser<'_> {
    fn parse_value(
        &mut self,
        stack: &mut Vec<Frame>,
        root: &mut Option<Value>,
    ) -> Result<(), PolicyError> {
        self.skip_whitespace();
        self.count_node()?;

        match self.peek() {
            Some(b'{') => {
                self.position += 1;
                self.push_container(
                    Frame::Object {
                        values: Map::new(),
                        state: FrameState::ObjectKeyOrEnd,
                        pending_key: None,
                    },
                    stack,
                )
            }
            Some(b'[') => {
                self.position += 1;
                self.push_container(
                    Frame::Array {
                        values: Vec::new(),
                        state: FrameState::ArrayValueOrEnd,
                    },
                    stack,
                )
            }
            Some(b'"') => {
                let value = Value::String(self.parse_string()?);
                self.attach(value, stack, root)
            }
            Some(b't') => {
                self.parse_literal(b"true")?;
                self.attach(Value::Bool(true), stack, root)
            }
            Some(b'f') => {
                self.parse_literal(b"false")?;
                self.attach(Value::Bool(false), stack, root)
            }
            Some(b'n') => {
                self.parse_literal(b"null")?;
                self.attach(Value::Null, stack, root)
            }
            Some(b'-' | b'0'..=b'9') => {
                let number = self.parse_number()?;
                self.attach(Value::Number(number), stack, root)
            }
            _ => Err(self.invalid("expected a JSON value")),
        }
    }

    fn push_container(&self, frame: Frame, stack: &mut Vec<Frame>) -> Result<(), PolicyError> {
        let depth = stack.len().saturating_add(1);
        check_depth(depth, self.limits.max_depth.min(MAX_SAFE_NESTING_DEPTH))?;
        stack.push(frame);
        Ok(())
    }

    fn close_frame(
        &self,
        stack: &mut Vec<Frame>,
        root: &mut Option<Value>,
    ) -> Result<(), PolicyError> {
        let frame = stack
            .pop()
            .ok_or_else(|| self.invalid("unexpected JSON container terminator"))?;
        let value = match frame {
            Frame::Array { values, .. } => Value::Array(values),
            Frame::Object { values, .. } => Value::Object(values),
        };
        self.attach(value, stack, root)
    }

    fn attach(
        &self,
        value: Value,
        stack: &mut [Frame],
        root: &mut Option<Value>,
    ) -> Result<(), PolicyError> {
        match stack.last_mut() {
            Some(Frame::Array { values, state }) if *state == FrameState::ArraySeparator => {
                values.push(value);
                Ok(())
            }
            Some(Frame::Object {
                values,
                state,
                pending_key,
            }) if *state == FrameState::ObjectSeparator => {
                let key = pending_key
                    .take()
                    .ok_or_else(|| self.invalid("JSON object member name is missing"))?;
                values.insert(key, value);
                Ok(())
            }
            None if root.is_none() => {
                *root = Some(value);
                Ok(())
            }
            _ => Err(self.invalid("unexpected JSON value")),
        }
    }

    fn set_state(&self, state: FrameState, stack: &mut [Frame]) -> Result<(), PolicyError> {
        let Some(frame) = stack.last_mut() else {
            return Err(self.invalid("JSON parser has no open container"));
        };
        match frame {
            Frame::Array { state: current, .. } if is_array_state(state) => *current = state,
            Frame::Object { state: current, .. } if !is_array_state(state) => *current = state,
            _ => return Err(self.invalid("JSON parser state does not match its container")),
        }
        Ok(())
    }

    fn set_pending_key(&self, key: String, stack: &mut [Frame]) -> Result<(), PolicyError> {
        match stack.last_mut() {
            Some(Frame::Object { pending_key, .. }) => {
                *pending_key = Some(key);
                Ok(())
            }
            _ => Err(self.invalid("JSON object parser state is invalid")),
        }
    }

    fn parse_string(&mut self) -> Result<String, PolicyError> {
        let start = self.position;
        if self.peek() != Some(b'"') {
            return Err(self.invalid("expected a JSON string"));
        }
        self.position += 1;

        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    self.position += 1;
                    let token = &self.bytes[start..self.position];
                    if !unicode_scalar_escapes_valid(token) {
                        return Err(non_scalar_string_error(self.position));
                    }
                    return serde_json::from_slice(token)
                        .map_err(|_| self.invalid("invalid JSON string"));
                }
                b'\\' => {
                    self.position += 1;
                    if self.peek().is_none() {
                        return Err(self.invalid("unterminated JSON escape"));
                    }
                    self.position += 1;
                }
                0..=0x1f => return Err(self.invalid("unescaped control character in JSON string")),
                _ => self.position += 1,
            }
        }

        Err(self.invalid("unterminated JSON string"))
    }

    fn parse_number(&mut self) -> Result<Number, PolicyError> {
        let start = self.position;
        while let Some(byte) = self.peek() {
            if is_whitespace(byte) || matches!(byte, b',' | b']' | b'}') {
                break;
            }
            self.position += 1;
        }
        let token = &self.bytes[start..self.position];
        if token.len() > MAX_NUMBER_LEXEME_BYTES {
            return Err(resource_error(
                "JSON number lexeme exceeds the byte limit",
                Some(start),
            ));
        }
        serde_json::from_slice(token).map_err(|_| self.invalid("invalid JSON number"))
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), PolicyError> {
        let end = self.position.saturating_add(literal.len());
        if self.bytes.get(self.position..end) != Some(literal) {
            return Err(self.invalid("invalid JSON literal"));
        }
        self.position = end;
        Ok(())
    }

    fn count_node(&mut self) -> Result<(), PolicyError> {
        count_checked_node(&mut self.nodes, self.limits.max_nodes)
            .map_err(|_| resource_error("JSON node limit exceeded", Some(self.position)))
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(is_whitespace) {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn invalid(&self, message: &str) -> PolicyError {
        invalid_error("policy_parse_error", message, self.position)
    }
}

fn unicode_scalar_escapes_valid(token: &[u8]) -> bool {
    let mut index = 1;
    let end = token.len().saturating_sub(1);
    while index < end {
        if token[index] != b'\\' {
            index += 1;
            continue;
        }

        let escape = index + 1;
        if token.get(escape) != Some(&b'u') {
            index = escape.saturating_add(1);
            continue;
        }

        let digits = escape.saturating_add(1);
        let Some(unit) = hex_code_unit(token.get(digits..digits.saturating_add(4))) else {
            index = digits.saturating_add(4);
            continue;
        };
        let after_unit = digits.saturating_add(4);

        if (0xd800..=0xdbff).contains(&unit) {
            if token.get(after_unit..after_unit.saturating_add(2)) != Some(b"\\u") {
                return false;
            }
            let low_start = after_unit.saturating_add(2);
            let Some(low) = hex_code_unit(token.get(low_start..low_start.saturating_add(4))) else {
                return false;
            };
            if !(0xdc00..=0xdfff).contains(&low) {
                return false;
            }
            index = low_start.saturating_add(4);
        } else if (0xdc00..=0xdfff).contains(&unit) {
            return false;
        } else {
            index = after_unit;
        }
    }
    true
}

fn hex_code_unit(digits: Option<&[u8]>) -> Option<u16> {
    let digits = digits?;
    if digits.len() != 4 {
        return None;
    }
    digits.iter().try_fold(0_u16, |value, digit| {
        let digit = match digit {
            b'0'..=b'9' => u16::from(*digit - b'0'),
            b'a'..=b'f' => u16::from(*digit - b'a' + 10),
            b'A'..=b'F' => u16::from(*digit - b'A' + 10),
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(digit)
    })
}

fn is_array_state(state: FrameState) -> bool {
    matches!(
        state,
        FrameState::ArrayValueOrEnd | FrameState::ArrayValue | FrameState::ArraySeparator
    )
}

fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn check_depth(depth: usize, limit: usize) -> Result<(), PolicyError> {
    if depth > limit {
        return Err(resource_error("JSON nesting depth limit exceeded", None));
    }
    Ok(())
}

fn count_checked_node(nodes: &mut usize, limit: usize) -> Result<(), PolicyError> {
    if *nodes >= limit {
        return Err(resource_error("JSON node limit exceeded", None));
    }
    *nodes += 1;
    Ok(())
}

fn add_checked_size(size: &mut usize, additional: usize, limit: usize) -> Result<(), PolicyError> {
    let Some(total) = size.checked_add(additional) else {
        return Err(resource_error("JSON value exceeds the byte limit", None));
    };
    if total > limit {
        return Err(resource_error("JSON value exceeds the byte limit", None));
    }
    *size = total;
    Ok(())
}

fn encoded_string_len(value: &str) -> Option<usize> {
    value.bytes().try_fold(2_usize, |size, byte| {
        size.checked_add(match byte {
            b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 2,
            0..=0x1f => 6,
            _ => 1,
        })
    })
}

fn duplicate_member_error(key: &str, offset: usize) -> PolicyError {
    PolicyError::new(
        PolicyErrorKind::Invalid,
        vec![Diagnostic {
            code: "policy_duplicate_member".to_owned(),
            path: String::new(),
            message: format!("duplicate decoded JSON member {key:?} at byte {offset}"),
        }],
    )
}

fn invalid_error(code: &str, message: &str, offset: usize) -> PolicyError {
    PolicyError::new(
        PolicyErrorKind::Invalid,
        vec![Diagnostic {
            code: code.to_owned(),
            path: String::new(),
            message: format!("{message} at byte {offset}"),
        }],
    )
}

fn non_scalar_string_error(offset: usize) -> PolicyError {
    invalid_error(
        "policy_string_non_scalar",
        "JSON string contains an unpaired Unicode surrogate",
        offset,
    )
}

fn resource_error(message: &str, offset: Option<usize>) -> PolicyError {
    let message = match offset {
        Some(offset) => format!("{message} at byte {offset}"),
        None => message.to_owned(),
    };
    PolicyError::new(
        PolicyErrorKind::ResourceLimit,
        vec![Diagnostic {
            code: "policy_resource_limit".to_owned(),
            path: String::new(),
            message,
        }],
    )
}

#[cfg(test)]
mod tests {
    use serde_json::{Number, Value};

    use super::{check_value_limits, parse_json, ParseLimits, MAX_NUMBER_LEXEME_BYTES};
    use crate::types::PolicyErrorKind;

    #[test]
    fn defaults_bound_bytes_depth_and_nodes() {
        let limits = ParseLimits::default();
        assert_eq!(limits.max_bytes, 1_048_576);
        assert_eq!(limits.max_depth, 64);
        assert_eq!(limits.max_nodes, 100_000);
    }

    #[test]
    fn rejects_duplicate_decoded_keys_at_every_depth() {
        for input in [
            br#"{"name":1,"\u006eame":2}"#.as_slice(),
            br#"{"outer":[{"name":1,"name":2}]}"#.as_slice(),
            br#"{"outer":[{"$serde_json::private::Number":1,"$serde_json::private:\u003aNumber":2}]}"#.as_slice(),
            r#"{"\uD83D\uDE00":1,"😀":2}"#.as_bytes(),
        ] {
            let error = parse_json(input, ParseLimits::default()).unwrap_err();
            assert_eq!(error.kind, PolicyErrorKind::Invalid);
            assert_eq!(error.diagnostics[0].code, "policy_duplicate_member");
        }
    }

    #[test]
    fn duplicate_is_detected_before_its_value_is_parsed() {
        let error =
            parse_json(br#"{"key":1,"key":,"unterminated""#, ParseLimits::default()).unwrap_err();
        assert_eq!(error.diagnostics[0].code, "policy_duplicate_member");
    }

    #[test]
    fn marker_named_extension_member_round_trips_as_an_object() {
        let value = parse_json(
            br#"{"extensions":{"x":{"$serde_json::private::Number":"1"}}}"#,
            ParseLimits::default(),
        )
        .unwrap();
        let encoded = serde_json::to_vec(&value).unwrap();
        let round_trip = parse_json(&encoded, ParseLimits::default()).unwrap();
        assert_eq!(round_trip, value);
        assert!(round_trip["extensions"]["x"].is_object());
        assert_eq!(
            round_trip["extensions"]["x"]["$serde_json::private::Number"],
            "1"
        );
    }

    #[test]
    fn distinct_marker_like_member_names_are_allowed() {
        let value = parse_json(
            br#"{"$serde_json::private::Number":1,"$serde_json::private:Number":2}"#,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(value["$serde_json::private::Number"], 1);
        assert_eq!(value["$serde_json::private:Number"], 2);
    }

    #[test]
    fn rejects_unpaired_surrogates_without_panicking_and_accepts_pairs() {
        for input in [br#""\uDEAD""#.as_slice(), br#""\uD800""#.as_slice()] {
            let result = std::panic::catch_unwind(|| parse_json(input, ParseLimits::default()));
            assert!(result.is_ok());
            let error = result.unwrap().unwrap_err();
            assert_eq!(error.kind, PolicyErrorKind::Invalid);
            assert_eq!(error.diagnostics[0].code, "policy_string_non_scalar");
        }

        let value = parse_json(
            r#"{"escaped":"\uD83D\uDE00","literal":"😀"}"#.as_bytes(),
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(value["escaped"], value["literal"]);
    }

    #[test]
    fn rejects_malformed_or_non_single_json_texts() {
        for input in [
            br#"{"x":1,}"#.as_slice(),
            br#"{"x":1}//comment"#.as_slice(),
            br#"{} {}"#.as_slice(),
            br#"{"x":NaN}"#.as_slice(),
            b"{\"x\":\xff}",
        ] {
            assert_eq!(
                parse_json(input, ParseLimits::default()).unwrap_err().kind,
                PolicyErrorKind::Invalid
            );
        }
        let invalid_utf8 = parse_json(b"{\"x\":\xff}", ParseLimits::default()).unwrap_err();
        assert_eq!(invalid_utf8.diagnostics[0].code, "policy_parse_error");
    }

    #[test]
    fn permits_whitespace_around_one_exact_json_value() {
        assert_eq!(
            parse_json(b" \n {\"x\":1} \r\t", ParseLimits::default()).unwrap(),
            serde_json::json!({ "x": 1 })
        );
    }

    #[test]
    fn reports_byte_depth_node_and_number_limits_as_resource_limits() {
        let base = ParseLimits::default();
        for (input, limits) in [
            (
                br#"null"#.as_slice(),
                ParseLimits {
                    max_bytes: 3,
                    ..base
                },
            ),
            (
                br#"[[0]]"#.as_slice(),
                ParseLimits {
                    max_depth: 1,
                    ..base
                },
            ),
            (
                br#"[0,1]"#.as_slice(),
                ParseLimits {
                    max_nodes: 2,
                    ..base
                },
            ),
        ] {
            assert_eq!(
                parse_json(input, limits).unwrap_err().kind,
                PolicyErrorKind::ResourceLimit
            );
        }
        let huge_exponent = format!("1e{}", "9".repeat(4_096));
        assert_eq!(
            parse_json(huge_exponent.as_bytes(), base).unwrap_err().kind,
            PolicyErrorKind::ResourceLimit
        );
        assert_eq!(
            parse_json(
                b"null",
                ParseLimits {
                    max_bytes: 0,
                    ..base
                }
            )
            .unwrap_err()
            .kind,
            PolicyErrorKind::ResourceLimit
        );
        assert_eq!(
            parse_json(
                b"null",
                ParseLimits {
                    max_nodes: 0,
                    ..base
                }
            )
            .unwrap_err()
            .kind,
            PolicyErrorKind::ResourceLimit
        );
    }

    #[test]
    fn configurable_depth_is_not_limited_by_serde_recursion() {
        let depth = 129;
        let mut input = vec![b'['; depth];
        input.push(b'0');
        input.extend(std::iter::repeat_n(b']', depth));
        let value = parse_json(
            &input,
            ParseLimits {
                max_depth: depth,
                ..ParseLimits::default()
            },
        )
        .unwrap();
        assert!(value.is_array());
    }

    #[test]
    fn explicit_depth_ceiling_is_enforced_even_for_unbounded_configuration() {
        let depth = 257;
        let mut input = vec![b'['; depth];
        input.push(b'0');
        input.extend(std::iter::repeat_n(b']', depth));
        let error = parse_json(
            &input,
            ParseLimits {
                max_depth: usize::MAX,
                ..ParseLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, PolicyErrorKind::ResourceLimit);
    }

    #[test]
    fn checks_caller_created_values_iteratively_and_bounds_compact_size() {
        let value = Value::Array(vec![Value::String("\n".to_owned())]);
        assert!(check_value_limits(&value, ParseLimits::default()).is_ok());
        assert_eq!(
            check_value_limits(
                &value,
                ParseLimits {
                    max_bytes: 4,
                    ..ParseLimits::default()
                }
            )
            .unwrap_err()
            .kind,
            PolicyErrorKind::ResourceLimit
        );
        assert_eq!(
            check_value_limits(
                &value,
                ParseLimits {
                    max_nodes: 0,
                    ..ParseLimits::default()
                }
            )
            .unwrap_err()
            .kind,
            PolicyErrorKind::ResourceLimit
        );
        assert_eq!(
            check_value_limits(
                &value,
                ParseLimits {
                    max_bytes: 0,
                    ..ParseLimits::default()
                }
            )
            .unwrap_err()
            .kind,
            PolicyErrorKind::ResourceLimit
        );
    }

    #[test]
    fn caller_created_values_obey_number_lexeme_limit() {
        let number =
            Number::from_string_unchecked(format!("1e{}", "9".repeat(MAX_NUMBER_LEXEME_BYTES - 1)));
        let value = Value::Number(number);
        let error = check_value_limits(&value, ParseLimits::default()).unwrap_err();
        assert_eq!(error.kind, PolicyErrorKind::ResourceLimit);
    }

    #[test]
    fn caller_created_values_reject_invalid_number_lexemes() {
        for lexeme in ["NaN", r#"{"$serde_json::private::Number":"1"}"#, "1 "] {
            let value = Value::Number(Number::from_string_unchecked(lexeme.to_owned()));
            let error = check_value_limits(&value, ParseLimits::default()).unwrap_err();
            assert_eq!(error.kind, PolicyErrorKind::Invalid, "{lexeme:?}");
            assert_eq!(error.diagnostics[0].code, "policy_parse_error");
        }
    }

    #[test]
    fn caller_created_large_exponent_numbers_remain_valid_json() {
        let value: Value = serde_json::from_str("1e400").unwrap();
        check_value_limits(&value, ParseLimits::default()).unwrap();
        let encoded = serde_json::to_vec(&value).unwrap();
        assert_eq!(parse_json(&encoded, ParseLimits::default()).unwrap(), value);
    }
}
