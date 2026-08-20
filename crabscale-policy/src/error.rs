//! Error type shared by the HUJSON parser, model deserialization, and
//! semantic validation.

use std::fmt;

/// An error produced while parsing or validating a policy file.
///
/// Every error carries a 1-based [`line`][HujsonError::line] (and, for syntax
/// errors, a column) so callers can point the user at the offending line.
/// The parser is written to never panic on malformed input: any problem is
/// reported as an [`Err`] through this type instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HujsonError {
    /// 1-based line number where the problem was detected.
    pub line: usize,
    /// 1-based column number where the problem was detected (syntax errors).
    pub column: usize,
    /// Human-readable description of the problem.
    pub message: String,
}

impl HujsonError {
    /// Build an error at a specific 1-based `(line, column)`.
    pub fn at(line: usize, column: usize, message: impl Into<String>) -> Self {
        HujsonError {
            line,
            column,
            message: message.into(),
        }
    }

    /// Build an error carrying only a line number (used by semantic checks
    /// that run after syntax parsing and have already lost column detail).
    pub fn at_line(line: usize, message: impl Into<String>) -> Self {
        HujsonError::at(line, 1, message)
    }

    /// Build an error at line 1 with no positional detail.
    pub fn new(message: impl Into<String>) -> Self {
        Self::at_line(1, message)
    }
}

impl fmt::Display for HujsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {} column {}: {}",
            self.line, self.column, self.message
        )
    }
}

impl std::error::Error for HujsonError {}
