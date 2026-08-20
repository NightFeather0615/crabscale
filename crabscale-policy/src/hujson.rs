//! A hand-rolled HUJSON parser.
//!
//! HUJSON is JSON extended with `//` line comments, `/* */` block comments,
//! and trailing commas. Everything else - object and array syntax, strings,
//! numbers, literals - is plain JSON as described by [Spec-Policy].
//!
//! The parser is intentionally written by hand (rather than delegating to a
//! JSON5 crate) so that:
//!
//! - syntax errors carry accurate 1-based line and column numbers;
//! - duplicate object keys can be detected and rejected;
//! - malformed input never panics; every failure is returned as a
//!   [`HujsonError`].
//!
//! [Spec-Policy]: https://github.com/NightFeather0615/crabscale/wiki/Spec-Policy.md

use serde_json::{Map, Number, Value};

use crate::HujsonError;

/// Parse `text` as a top-level HUJSON value.
///
/// This is the entry point for the syntax layer. It accepts the full policy
/// document (a JSON object) as well as any other well-formed HUJSON value.
/// After the value is consumed the whole input must be exhausted, otherwise a
/// "unexpected trailing content" error is returned.
pub fn parse(text: &str) -> Result<Value, HujsonError> {
    let mut parser = Parser::new(text);
    let value = parser.parse_value()?;
    parser.skip_ws()?;
    if let Some(c) = parser.peek() {
        return Err(parser.err_here(format!(
            "unexpected trailing content `{c}` after the document"
        )));
    }
    Ok(value)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    /// 1-based line of `pos`.
    line: usize,
    /// 1-based column of `pos`.
    col: usize,
}

impl Parser {
    fn new(text: &str) -> Self {
        Parser {
            chars: text.chars().collect(),
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_next(&self) -> Option<char> {
        self.chars.get(self.pos + 1).copied()
    }

    /// Consume one character and update the line/column bookkeeping.
    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied()?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    /// Consume the current character, asserting it equals `expected`.
    fn expect(&mut self, expected: char, context: &str) -> Result<(), HujsonError> {
        let c = self
            .bump()
            .ok_or_else(|| self.err_here(format!("unexpected end of input {context}")))?;
        if c != expected {
            return Err(self.err_here(format!("expected `{expected}` {context}, found `{c}`")));
        }
        Ok(())
    }

    fn err_here(&self, message: impl Into<String>) -> HujsonError {
        HujsonError::at(self.line, self.col, message)
    }

    fn err_at(&self, line: usize, col: usize, message: impl Into<String>) -> HujsonError {
        HujsonError::at(line, col, message)
    }

    /// Skip whitespace, `//` line comments, and `/* */` block comments.
    fn skip_ws(&mut self) -> Result<(), HujsonError> {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\n' | '\r') => {
                    self.bump();
                }
                Some('/') if self.peek_next() == Some('/') => {
                    self.bump();
                    self.bump();
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some('/') if self.peek_next() == Some('*') => {
                    let (start_line, start_col) = (self.line, self.col);
                    self.bump();
                    self.bump();
                    loop {
                        match self.peek() {
                            None => {
                                return Err(self.err_at(
                                    start_line,
                                    start_col,
                                    "unterminated block comment",
                                ));
                            }
                            Some('*') if self.peek_next() == Some('/') => {
                                self.bump();
                                self.bump();
                                break;
                            }
                            Some(_) => {
                                self.bump();
                            }
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn parse_value(&mut self) -> Result<Value, HujsonError> {
        self.skip_ws()?;
        match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => Ok(Value::String(self.parse_string()?)),
            Some('t') => self.parse_literal("true", Value::Bool(true)),
            Some('f') => self.parse_literal("false", Value::Bool(false)),
            Some('n') => self.parse_literal("null", Value::Null),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            Some(c) => Err(self.err_here(format!("unexpected character `{c}`"))),
            None => Err(self.err_here("unexpected end of input")),
        }
    }

    fn parse_object(&mut self) -> Result<Value, HujsonError> {
        self.expect('{', "when starting an object")?;
        let mut map = Map::new();
        self.skip_ws()?;
        if self.peek() == Some('}') {
            self.bump();
            return Ok(Value::Object(map));
        }
        loop {
            let (key_line, key_col) = (self.line, self.col);
            self.skip_ws()?;
            let key = match self.peek() {
                Some('"') => self.parse_string()?,
                Some(c) => {
                    return Err(self.err_here(format!("expected a quoted object key, found `{c}`")));
                }
                None => return Err(self.err_here("unexpected end of input in object")),
            };
            if map.contains_key(&key) {
                return Err(self.err_at(
                    key_line,
                    key_col,
                    format!("duplicate object key `{key}`"),
                ));
            }
            self.skip_ws()?;
            self.expect(':', "after an object key")?;
            self.skip_ws()?;
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_ws()?;
            match self.peek() {
                Some(',') => {
                    self.bump();
                    self.skip_ws()?;
                    if self.peek() == Some('}') {
                        // Trailing comma before the closing brace.
                        self.bump();
                        return Ok(Value::Object(map));
                    }
                }
                Some('}') => {
                    self.bump();
                    return Ok(Value::Object(map));
                }
                Some(c) => {
                    return Err(
                        self.err_here(format!("expected `,` or `}}` in object, found `{c}`"))
                    );
                }
                None => return Err(self.err_here("unexpected end of input in object")),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Value, HujsonError> {
        self.expect('[', "when starting an array")?;
        let mut values = Vec::new();
        self.skip_ws()?;
        if self.peek() == Some(']') {
            self.bump();
            return Ok(Value::Array(values));
        }
        loop {
            let value = self.parse_value()?;
            values.push(value);
            self.skip_ws()?;
            match self.peek() {
                Some(',') => {
                    self.bump();
                    self.skip_ws()?;
                    if self.peek() == Some(']') {
                        // Trailing comma before the closing bracket.
                        self.bump();
                        return Ok(Value::Array(values));
                    }
                }
                Some(']') => {
                    self.bump();
                    return Ok(Value::Array(values));
                }
                Some(c) => {
                    return Err(self.err_here(format!("expected `,` or `]` in array, found `{c}`")));
                }
                None => return Err(self.err_here("unexpected end of input in array")),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, HujsonError> {
        self.expect('"', "when starting a string")?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(self.err_here("unterminated string")),
                Some('"') => {
                    self.bump();
                    return Ok(out);
                }
                Some('\\') => {
                    self.bump();
                    self.parse_escape(&mut out)?;
                }
                Some(c) if c.is_control() => {
                    return Err(self.err_here("unescaped control character in string"));
                }
                Some(c) => {
                    out.push(c);
                    self.bump();
                }
            }
        }
    }

    fn parse_escape(&mut self, out: &mut String) -> Result<(), HujsonError> {
        let Some(c) = self.bump() else {
            return Err(self.err_here("unterminated string after escape"));
        };
        match c {
            '"' => {
                out.push('"');
                Ok(())
            }
            '\\' => {
                out.push('\\');
                Ok(())
            }
            '/' => {
                out.push('/');
                Ok(())
            }
            'b' => {
                out.push('\u{0008}');
                Ok(())
            }
            'f' => {
                out.push('\u{000c}');
                Ok(())
            }
            'n' => {
                out.push('\n');
                Ok(())
            }
            'r' => {
                out.push('\r');
                Ok(())
            }
            't' => {
                out.push('\t');
                Ok(())
            }
            'u' => self.parse_unicode_escape(out),
            other => Err(self.err_here(format!("invalid escape sequence `\\{other}`"))),
        }
    }

    fn parse_unicode_escape(&mut self, out: &mut String) -> Result<(), HujsonError> {
        let first = self.parse_hex_quad()?;
        if (0xd800..=0xdbff).contains(&first) {
            // High surrogate: look ahead for a `\\uXXXX` low surrogate.
            if self.peek() == Some('\\') && self.peek_next() == Some('u') {
                self.bump();
                self.bump();
                let second = self.parse_hex_quad()?;
                if (0xdc00..=0xdfff).contains(&second) {
                    let scalar = 0x10000
                        + ((u32::from(first) - 0xd800) << 10)
                        + (u32::from(second) - 0xdc00);
                    let ch = char::from_u32(scalar)
                        .ok_or_else(|| self.err_here("invalid unicode surrogate pair"))?;
                    out.push(ch);
                    return Ok(());
                }
                // A lone high surrogate or an invalid following escape is not
                // representable in a Rust `String`; emit the replacement char.
                out.push('\u{fffd}');
                if let Some(ch) = char::from_u32(u32::from(second)) {
                    out.push(ch);
                }
                return Ok(());
            }
            out.push('\u{fffd}');
            Ok(())
        } else if (0xdc00..=0xdfff).contains(&first) {
            // A lone low surrogate.
            out.push('\u{fffd}');
            Ok(())
        } else {
            let ch = char::from_u32(u32::from(first))
                .ok_or_else(|| self.err_here("invalid unicode escape"))?;
            out.push(ch);
            Ok(())
        }
    }

    fn parse_hex_quad(&mut self) -> Result<u16, HujsonError> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            let Some(c) = self.bump() else {
                return Err(self.err_here("truncated `\\uXXXX` escape"));
            };
            let digit = c
                .to_digit(16)
                .ok_or_else(|| self.err_here(format!("invalid hex digit `{c}` in `\\uXXXX`")))?;
            value = value * 16 + digit;
        }
        Ok(value as u16)
    }

    fn parse_literal(&mut self, literal: &str, value: Value) -> Result<Value, HujsonError> {
        let (start_line, start_col) = (self.line, self.col);
        for expected in literal.chars() {
            match self.bump() {
                Some(actual) if actual == expected => {}
                _ => {
                    return Err(self.err_at(
                        start_line,
                        start_col,
                        format!("invalid literal `{literal}`"),
                    ));
                }
            }
        }
        // The literal must not be glued to an otherwise-invalid identifier
        // character (e.g. `truex` or `null5`).
        if let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                return Err(self.err_at(
                    start_line,
                    start_col,
                    format!("invalid literal `{literal}`"),
                ));
            }
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, HujsonError> {
        let (start_line, start_col) = (self.line, self.col);
        let start_pos = self.pos;

        if self.peek() == Some('-') {
            self.bump();
        }
        // Integer part.
        match self.peek() {
            Some('0') => {
                self.bump();
            }
            Some(c) if c.is_ascii_digit() && c != '0' => {
                self.bump();
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.bump();
                }
            }
            _ => {
                return Err(self.err_here("invalid number: expected a digit"));
            }
        }
        // Fraction part.
        if self.peek() == Some('.') {
            self.bump();
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(self.err_here("invalid number: expected a digit after `.`"));
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.bump();
            }
        }
        // Exponent part.
        if matches!(self.peek(), Some('e' | 'E')) {
            self.bump();
            if matches!(self.peek(), Some('+' | '-')) {
                self.bump();
            }
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(self.err_here("invalid number: expected a digit in exponent"));
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.bump();
            }
        }
        // Disallow junk glued to the number such as `1.2.3` or `123abc`.
        if let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '.' {
                self.bump();
                let token: String = self.chars[start_pos..self.pos].iter().collect();
                return Err(self.err_at(
                    start_line,
                    start_col,
                    format!("invalid number `{token}`"),
                ));
            }
        }

        let token: String = self.chars[start_pos..self.pos].iter().collect();
        let number = parse_json_number(&token)
            .map_err(|msg| self.err_at(start_line, start_col, format!("invalid number: {msg}")))?;
        Ok(Value::Number(number))
    }
}

fn parse_json_number(token: &str) -> Result<Number, String> {
    if token.contains(['.', 'e', 'E']) {
        let value: f64 = token
            .parse()
            .map_err(|_| format!("`{token}` cannot be represented"))?;
        Number::from_f64(value).ok_or_else(|| format!("`{token}` is not a valid number"))
    } else {
        if let Ok(value) = token.parse::<i64>() {
            return Ok(Number::from(value));
        }
        if let Ok(value) = token.parse::<u64>() {
            return Ok(Number::from(value));
        }
        Err(format!("`{token}` is not a valid integer"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(input: &str) -> Value {
        parse(input).unwrap_or_else(|err| panic!("expected parse success, got {err}"))
    }

    fn parse_err_line(input: &str) -> usize {
        parse(input).expect_err("expected parse failure").line
    }

    #[test]
    fn minimal_object() {
        assert_eq!(
            parse_ok(r#"{ "a": 1, "b": [1, 2, 3], "c": null, "d": true }"#),
            serde_json::json!({ "a": 1, "b": [1, 2, 3], "c": null, "d": true })
        );
    }

    #[test]
    fn accepts_line_comments() {
        assert_eq!(
            parse_ok("{\n  // a comment\n  \"a\": 1 // trailing\n}"),
            serde_json::json!({ "a": 1 })
        );
    }

    #[test]
    fn accepts_block_comments() {
        assert_eq!(
            parse_ok("/* header */\n{ \"a\": /* inline */ 1 }"),
            serde_json::json!({ "a": 1 })
        );
    }

    #[test]
    fn accepts_trailing_commas() {
        assert_eq!(
            parse_ok(
                r#"{
                    "a": [1, 2,],
                    "b": {"x": 1,},
                }"#
            ),
            serde_json::json!({ "a": [1, 2], "b": { "x": 1 } })
        );
    }

    #[test]
    fn string_escapes() {
        assert_eq!(
            parse_ok(r#""a\nb\tc\"d\\e\u0041/f""#),
            Value::String("a\nb\tc\"d\\eA/f".to_string())
        );
    }

    #[test]
    fn unicode_surrogate_pair() {
        assert_eq!(
            parse_ok(r#""\uD83D\uDE00""#),
            Value::String("😀".to_string())
        );
    }

    #[test]
    fn duplicate_key_rejected() {
        let err = parse(r#"{ "a": 1, "a": 2 }"#).expect_err("duplicate must fail");
        assert!(err.message.contains("duplicate"));
        assert_eq!(err.line, 1);
    }

    #[test]
    fn duplicate_key_line_reported() {
        let line = parse_err_line("{\n  \"a\": 1,\n  \"a\": 2,\n}");
        assert_eq!(line, 3);
    }

    #[test]
    fn unterminated_string_reports_line() {
        let err = parse("{\n  \"a\": \"oops\n}").expect_err("must fail");
        assert!(
            err.message.contains("string"),
            "unexpected message: {}",
            err.message
        );
        assert_eq!(err.line, 2);
    }

    #[test]
    fn unterminated_block_comment_reports_line() {
        let err = parse("{\n  /* oops\n}").expect_err("must fail");
        assert!(err.message.contains("unterminated block comment"));
        assert_eq!(err.line, 2);
    }

    #[test]
    fn malformed_numbers_rejected() {
        for bad in ["01", "1.", "1.2.3", "-", "1e", "1e+"] {
            let err = parse(bad).expect_err("must fail");
            assert!(!err.message.is_empty(), "no message for {bad}");
        }
    }

    #[test]
    fn valid_numbers() {
        assert_eq!(parse_ok("0"), serde_json::json!(0));
        assert_eq!(parse_ok("-12"), serde_json::json!(-12));
        assert_eq!(parse_ok("1.5e3"), serde_json::json!(1500.0));
        assert_eq!(parse_ok("2.5"), serde_json::json!(2.5));
    }

    #[test]
    fn trailing_garbage_rejected() {
        let err = parse("{} junk").expect_err("must fail");
        assert!(err.message.contains("trailing"));
    }

    #[test]
    fn empty_input_rejected() {
        let err = parse("").expect_err("must fail");
        assert!(err.message.contains("end of input"));
    }

    #[test]
    fn never_panics_on_fuzzish_input() {
        let inputs = [
            "",
            "{",
            "}",
            "[",
            "]",
            "{,}",
            "[a]",
            "\"unterminated",
            "/* nope",
            "{\"a\":}",
            "{\"a\":1,,}",
            "[1,,2]",
            "tru",
            "truestory",
            "nullx",
            "1 2",
            "\"\\x\"",
        ];
        for input in inputs {
            // Every malformed input must return Err, never panic.
            assert!(parse(input).is_err(), "expected Err for {input:?}");
        }
    }

    #[test]
    fn nested_comment_does_not_consume_string_slashes() {
        // A `//` inside a string is data, not a comment.
        assert_eq!(
            parse_ok(r#"{ "url": "http://example.com/x", }"#),
            serde_json::json!({ "url": "http://example.com/x" })
        );
    }
}
