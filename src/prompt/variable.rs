use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;
use std::convert::TryInto;

use anyhow::Context as _;
use colorful::Colorful;
use bigdecimal::BigDecimal;
use edgedb_protocol::value::Value;
use num_bigint::ToBigInt;
use rustyline::completion::Completer;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::{Validator, ValidationResult, ValidationContext};
use rustyline::{Helper, Context};


#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", description)]
    Mistake { offset: Option<usize>, description: String },
    #[error("value is incomplete")]
    Incomplete,
}

fn no_pos_err<E: fmt::Display>(err: E) -> Error {
    Error::Mistake { offset: None, description: err.to_string() }
}

pub trait VariableInput: fmt::Debug + Send + Sync + 'static {
    fn parse(&self, input: &str, top: bool) -> Result<Value, Error>;
    fn type_name(&self) -> &str;
}

#[derive(Debug)]
pub struct Str;

impl VariableInput for Str {
    fn type_name(&self) -> &str { "str" }
    fn parse(&self, input: &str, top: bool) -> Result<Value, Error> {
        if top {
            Ok(Value::Str(input.into()))
        } else {
            // This is hacky, but use the json parser
            // TODO: ... use a real parser for edgedb strings
            match serde_json::from_str::<String>(input) {
                Err(e) if e.classify()  == serde_json::error::Category::Eof
                    => Err(Error::Incomplete),
                Err(e) => Err(no_pos_err(e)),
                Ok(d) => Ok(Value::Str(d)),
            }
        }
    }
}

#[derive(Debug)]
pub struct Uuid;

impl VariableInput for Uuid {
    fn type_name(&self) -> &str { "uuid" }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        Ok(Value::Uuid(input.parse().map_err(no_pos_err)?))
    }
}

#[derive(Debug)]
pub struct Int16;

impl VariableInput for Int16 {
    fn type_name(&self) -> &str { "int16" }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        Ok(Value::Int16(input.parse().map_err(no_pos_err)?))
    }
}

#[derive(Debug)]
pub struct Int32;

impl VariableInput for Int32 {
    fn type_name(&self) -> &str { "int32" }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        Ok(Value::Int32(input.parse().map_err(no_pos_err)?))
    }
}

#[derive(Debug)]
pub struct Int64;

impl VariableInput for Int64 {
    fn type_name(&self) -> &str { "int64" }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        Ok(Value::Int64(input.parse().map_err(no_pos_err)?))
    }
}

#[derive(Debug)]
pub struct Float32;

impl VariableInput for Float32 {
    fn type_name(&self) -> &str { "float32" }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        Ok(Value::Float32(input.parse().map_err(no_pos_err)?))
    }
}

#[derive(Debug)]
pub struct Float64;

impl VariableInput for Float64 {
    fn type_name(&self) -> &str { "float64" }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        Ok(Value::Float32(input.parse().map_err(no_pos_err)?))
    }
}

#[derive(Debug)]
pub struct Bool;

impl VariableInput for Bool {
    fn type_name(&self) -> &str { "bool" }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        Ok(Value::Bool(input.parse().map_err(no_pos_err)?))
    }
}

#[derive(Debug)]
pub struct BigInt;

impl VariableInput for BigInt {
    fn type_name(&self) -> &str { "bigint" }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        let dec: BigDecimal = input.parse().map_err(no_pos_err)?;
        let int = dec.to_bigint()
            .context("number is not an integer")
            .map_err(no_pos_err)?;
        let int = int.try_into().map_err(no_pos_err)?;
        Ok(Value::BigInt(int))
    }
}

#[derive(Debug)]
pub struct Decimal;

impl VariableInput for Decimal {
    fn type_name(&self) -> &str { "decimal" }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        let dec: BigDecimal = input.parse().map_err(no_pos_err)?;
        let dec = dec.try_into().map_err(no_pos_err)?;
        Ok(Value::Decimal(dec))
    }
}

#[derive(Debug)]
pub struct Json;

impl VariableInput for Json {
    fn type_name(&self) -> &str { "json" }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        match serde_json::from_str::<serde_json::Value>(input) {
            Err(e) if e.classify()  == serde_json::error::Category::Eof
            => Err(Error::Incomplete),
            Err(e) => Err(no_pos_err(e)),
            Ok(_) => Ok(Value::Json(input.into())),
        }
    }
}

fn partial_parse(var: &dyn VariableInput, input: &str)
                 -> Result<(Value, usize), Error>
{
    let mut end = input.len();
    loop {
        if end == 0 {
            var.parse(input, false)?;
            panic!("parse should have failed!");
        }
        if !input.is_char_boundary(end) {
            end -= 1;
            continue;
        }
        match var.parse(&input[.. end], false) {
            Ok(val) => { return Ok((val, end)); }
            Err(_) => { end -= 1; }
        }
    }
}

fn skip_whitespace(input: &[u8], mut idx: usize) -> usize {
    loop {
        if idx == input.len() { break };
        let c = char::from_u32(input[idx].into()).unwrap();
        if !c.is_ascii_whitespace() { break };
        idx += 1;
    }
    return idx;
}

#[derive(Debug)]
pub struct Array {
    pub elem: Arc<dyn VariableInput>,
    pub name: String,
}

impl Array {
    pub fn new(elem: Arc<dyn VariableInput>) -> Array {
        Array {
            name: format!("array<{}>", elem.type_name()),
            elem: elem,
        }
    }
}

impl VariableInput for Array {
    fn type_name(&self) -> &str { self.name.as_str() }
    fn parse(&self, input: &str, _top: bool) -> Result<Value, Error> {
        let binput = input.as_bytes();

        if binput.get(0) != Some(&b'[') {
            return Err(Error::Mistake {
                offset: None, description: "array must start with [".to_string()
            })
        }
        let mut idx = 1;
        idx = skip_whitespace(binput, idx);
        let mut vs = Vec::new();
        loop {
            match partial_parse(&*self.elem, &input[idx ..]) {
                Ok((v, end)) => {
                    let orig = idx;
                    vs.push(v);
                    idx += end;
                    idx = skip_whitespace(binput, idx);

                    if binput.get(idx) == Some(&b']') { break };
                    if binput.get(idx) != Some(&b',') {
                        if idx == input.len() {
                            return Err(Error::Incomplete);
                        } else {
                            self.elem.parse(&input[orig ..], false)?;
                            panic!("succeeded??");
                        }
                    }
                    idx += 1;
                    idx = skip_whitespace(binput, idx);
                }
                Err(e) => {
                    if idx != input.len() &&
                        binput.get(idx) != Some(&b']') {
                        return Err(e);
                    }

                    break;
                }
            }
        }
        if binput.get(idx) != Some(&b']') {
            return Err(Error::Incomplete);
        }
        if idx + 1 != input.len() {
            return Err(Error::Mistake {
                offset: Some(idx + 1),
                description: "trailing garbage".to_string(),
            })
        }
        Ok(Value::Array(vs))
    }
}

pub struct VarHelper {
    var_type: Arc<dyn VariableInput>,
}

pub struct ErrorHint(String);

impl rustyline::hint::Hint for ErrorHint {
    fn completion(&self) -> Option<&str> { None }
    fn display(&self) -> &str { self.0.as_ref() }
}

impl VarHelper {
    pub fn new(var_type: Arc<dyn VariableInput>) -> VarHelper {
        VarHelper {
            var_type,
        }
    }
}

impl Helper for VarHelper {}
impl Hinter for VarHelper {
    type Hint = ErrorHint;
    fn hint(&self, line: &str, _pos: usize, _ctx: &Context)
        -> Option<Self::Hint>
    {
        if line == "" {  // be friendly from the start
            return None;
        }
        match self.var_type.parse(line, true) {
            Ok(_) => None,
            Err(Error::Incomplete) => None,
            Err(e) => Some(ErrorHint(format!(" -- {}", e))),
        }
    }
}

impl Highlighter for VarHelper {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        match self.var_type.parse(line, true) {
            Ok(_) => line.into(),
            Err(_) => line.light_red().to_string().into(),
        }
    }
    fn highlight_hint<'h>(&self, hint: &'h str) -> std::borrow::Cow<'h, str> {
        return hint.rgb(0x56, 0x56, 0x56).to_string().into()
    }
    fn highlight_char<'l>(&self, _line: &'l str, _pos: usize) -> bool {
        // needed to highlight hint
        true
    }
    fn has_continuation_prompt(&self) -> bool {
        true
    }
}

impl Validator for VarHelper {
    fn validate(&self, ctx: &mut ValidationContext)
        -> Result<ValidationResult, ReadlineError>
    {
        match self.var_type.parse(ctx.input(), true) {
            Ok(_) => Ok(ValidationResult::Valid(None)),
            Err(Error::Incomplete) => Ok(ValidationResult::Incomplete),
            Err(e) => Ok(ValidationResult::Invalid(
                Some(format!(" -- {}", e))
            )),
        }
    }
}

impl Completer for VarHelper {
    type Candidate = String;
    fn complete(&self, _line: &str, pos: usize, _ctx: &Context)
        -> Result<(usize, Vec<Self::Candidate>), ReadlineError>
    {
        Ok((pos, Vec::new()))
    }
}
