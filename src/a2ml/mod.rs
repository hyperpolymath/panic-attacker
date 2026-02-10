// SPDX-License-Identifier: PMPL-1.0-or-later

//! Minimal A2ML parser and Nickel exporter

use crate::report::formatter::nickel_escape_string;
use crate::report::ReportOutputFormat;
use crate::storage::StorageMode;
use anyhow::{anyhow, Context, Result};
use serde_json;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Manifest {
    root_name: String,
    entries: Vec<Sexpr>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            root_name: "manifest".to_string(),
            entries: Vec::new(),
        }
    }
}

impl Manifest {
    pub fn load_default() -> Result<Self> {
        let path = PathBuf::from("AI.a2ml");
        Self::load(&path)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading A2ML manifest {}", path.display()))?;
        let mut parser = Parser::new(&raw);
        let tree = parser.parse_all()?;
        if let Sexpr::List(mut items) = tree {
            if let Some(Sexpr::Atom(root)) = items.first() {
                let root_name = root.clone();
                items.remove(0);
                return Ok(Self {
                    root_name,
                    entries: items,
                });
            }
        }
        Err(anyhow!("unexpected A2ML manifest structure"))
    }

    pub fn report_formats(&self) -> Vec<ReportOutputFormat> {
        self.section_entries("reports")
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|(key, _)| key == "formats")
                    .map(|(_, groups)| {
                        groups.iter().flat_map(|values| {
                            values.iter().filter_map(|value| match value {
                                Sexpr::String(text) => ReportOutputFormat::parse(text),
                                Sexpr::Atom(atom) => ReportOutputFormat::parse(atom),
                                _ => None,
                            })
                        })
                    })
                    .map(|iter| iter.collect::<Vec<_>>())
            })
            .filter(|formats: &Vec<ReportOutputFormat>| !formats.is_empty())
            .unwrap_or_else(|| vec![ReportOutputFormat::Json, ReportOutputFormat::Nickel])
    }

    pub fn storage_modes(&self) -> Vec<StorageMode> {
        self.section_entries("reports")
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|(key, _)| key == "storage-targets")
                    .map(|(_, groups)| {
                        groups
                            .iter()
                            .flat_map(|values| {
                                values.iter().filter_map(|value| match value {
                                    Sexpr::String(text) => StorageMode::from_str(text),
                                    Sexpr::Atom(atom) => StorageMode::from_str(atom),
                                    _ => None,
                                })
                            })
                            .collect::<Vec<_>>()
                    })
            })
            .filter(|modes: &Vec<StorageMode>| !modes.is_empty())
            .unwrap_or_else(|| vec![StorageMode::Filesystem])
    }

    pub fn to_nickel(&self) -> String {
        let entries = gather_entries(&self.entries);
        let body = record_to_nickel(&entries);
        format!("let {} = {};\n{}", self.root_name, body, self.root_name)
    }

    fn section_entries(&self, key: &str) -> Option<Vec<(String, Vec<Vec<Sexpr>>)>> {
        self.entries.iter().find_map(|entry| {
            if let Sexpr::List(list) = entry {
                if let Some(Sexpr::Atom(name)) = list.first() {
                    if name == key {
                        return Some(gather_entries(&list[1..]));
                    }
                }
            }
            None
        })
    }
}

#[derive(Clone, Debug)]
enum Sexpr {
    Atom(String),
    String(String),
    List(Vec<Sexpr>),
}

struct Parser<'a> {
    chars: std::str::Chars<'a>,
    peeked: Option<Option<char>>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.chars(),
            peeked: None,
        }
    }

    fn peek(&mut self) -> Option<char> {
        if let Some(opt) = self.peeked {
            opt
        } else {
            let opt = self.chars.clone().next();
            self.peeked = Some(opt);
            opt
        }
    }

    fn next(&mut self) -> Option<char> {
        if let Some(opt) = self.peeked.take() {
            if let Some(ch) = opt {
                self.chars.next();
                Some(ch)
            } else {
                None
            }
        } else {
            self.chars.next()
        }
    }

    fn skip_whitespace(&mut self) {
        loop {
            match self.peek() {
                Some(ch) if ch.is_whitespace() => {
                    self.next();
                }
                Some('#') => {
                    while let Some(ch) = self.next() {
                        if ch == '\n' {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    }

    fn parse_all(&mut self) -> Result<Sexpr> {
        self.skip_whitespace();
        let expr = self.parse_expr()?;
        self.skip_whitespace();
        if self.peek().is_some() {
            Err(anyhow!("extra tokens after manifest"))
        } else {
            Ok(expr)
        }
    }

    fn parse_expr(&mut self) -> Result<Sexpr> {
        self.skip_whitespace();
        match self.peek() {
            Some('(') => self.parse_list(),
            Some('"') => self.parse_string(),
            Some(ch) => {
                if ch == ')' {
                    Err(anyhow!("unexpected closing parenthesis"))
                } else {
                    self.parse_atom()
                }
            }
            None => Err(anyhow!("unexpected EOF while parsing A2ML")),
        }
    }

    fn parse_list(&mut self) -> Result<Sexpr> {
        self.next(); // consume '('
        let mut items = Vec::new();
        loop {
            self.skip_whitespace();
            match self.peek() {
                Some(')') => {
                    self.next();
                    break;
                }
                Some(_) => items.push(self.parse_expr()?),
                None => return Err(anyhow!("unterminated list")),
            }
        }
        Ok(Sexpr::List(items))
    }

    fn parse_string(&mut self) -> Result<Sexpr> {
        self.next(); // consume '"'
        let mut value = String::new();
        while let Some(ch) = self.next() {
            match ch {
                '"' => return Ok(Sexpr::String(value)),
                '\\' => {
                    if let Some(esc) = self.next() {
                        let replacement = match esc {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            '"' => '"',
                            '\\' => '\\',
                            other => other,
                        };
                        value.push(replacement);
                    }
                }
                other => value.push(other),
            }
        }
        Err(anyhow!("unterminated string literal"))
    }

    fn parse_atom(&mut self) -> Result<Sexpr> {
        let mut value = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() || ch == '(' || ch == ')' {
                break;
            }
            value.push(ch);
            self.next();
        }
        if value.is_empty() {
            Err(anyhow!("unexpected token"))
        } else {
            Ok(Sexpr::Atom(value))
        }
    }
}

fn gather_entries(entries: &[Sexpr]) -> Vec<(String, Vec<Vec<Sexpr>>)> {
    let mut grouped: Vec<(String, Vec<Vec<Sexpr>>)> = Vec::new();
    for entry in entries {
        if let Sexpr::List(inner) = entry {
            if let Some(Sexpr::Atom(key)) = inner.first() {
                let values = inner[1..].to_vec();
                if let Some((_, bucket)) = grouped.iter_mut().find(|(existing, _)| existing == key)
                {
                    bucket.push(values);
                } else {
                    grouped.push((key.clone(), vec![values]));
                }
            }
        }
    }
    grouped
}

fn record_to_nickel(entries: &[(String, Vec<Vec<Sexpr>>)]) -> String {
    let lines: Vec<String> = entries
        .iter()
        .map(|(key, groups)| {
            let value = if groups.len() == 1 {
                values_to_nickel(&groups[0])
            } else {
                let array = groups
                    .iter()
                    .map(|values| values_to_nickel(values))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}]", array)
            };
            format!("{} = {}", key_to_nickel(key), value)
        })
        .collect();
    format!("{{\n    {}\n}}", lines.join(";\n    "))
}

fn values_to_nickel(values: &[Sexpr]) -> String {
    match values.len() {
        0 => "null".to_string(),
        1 => value_to_nickel(&values[0]),
        _ => {
            if values.iter().all(|v| matches!(v, Sexpr::List(inner) if inner.first().map(|c| matches!(c, Sexpr::Atom(_))).unwrap_or(false))) {
                let nested_entries = gather_entries(values);
                record_to_nickel(&nested_entries)
            } else {
                let list = values
                    .iter()
                    .map(value_to_nickel)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}]", list)
            }
        }
    }
}

fn value_to_nickel(value: &Sexpr) -> String {
    match value {
        Sexpr::String(text) => nickel_escape_string(text),
        Sexpr::Atom(text) => nickel_escape_string(text),
        Sexpr::List(list) => {
            if list.is_empty() {
                "{}".to_string()
            } else if list.iter().all(|entry| {
                matches!(entry, Sexpr::List(inner) if inner.first().map(|c| matches!(c, Sexpr::Atom(_))).unwrap_or(false))
            }) {
                let nested_entries = gather_entries(list);
                record_to_nickel(&nested_entries)
            } else {
                let inner = list
                    .iter()
                    .map(value_to_nickel)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}]", inner)
            }
        }
    }
}

fn key_to_nickel(key: &str) -> String {
    if key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        key.to_string()
    } else {
        serde_json::to_string(key).unwrap_or_else(|_| format!("\"{}\"", key))
    }
}
