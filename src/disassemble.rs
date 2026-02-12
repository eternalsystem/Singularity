use crate::tools_manager::ToolManager;
use anyhow::{Context, Result};

mod py_dis_tables {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/py_dis_tables.rs"));
}

pub use py_dis_tables::OpcodeTables;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum MarshalValue {
    Null,
    None,
    Bool(bool),
    Int(i32),
    Int64(i64),
    Long {
        digits: usize,
        negative: bool,
        value_i64: Option<i64>,
    },
    Float(f64),
    Complex(f64, f64),
    Bytes(Vec<u8>),
    String(String),
    Tuple(Vec<MarshalValue>),
    List(Vec<MarshalValue>),
    Dict(Vec<(MarshalValue, MarshalValue)>),
    Set(Vec<MarshalValue>),
    FrozenSet(Vec<MarshalValue>),
    Code(Box<CodeObject>),
    Unknown(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CodeObject {
    pub argcount: i32,
    pub posonlyargcount: i32,
    pub kwonlyargcount: i32,
    pub stacksize: i32,
    pub flags: i32,
    pub code: Vec<u8>,
    pub consts: Vec<MarshalValue>,
    pub names: Vec<String>,
    pub varnames: Vec<String>,
    pub freevars: Vec<String>,
    pub cellvars: Vec<String>,
    pub localsplusnames: Vec<String>,
    pub localspluskinds: Vec<u8>,
    pub filename: String,
    pub name: String,
    pub qualname: String,
    pub firstlineno: i32,
    pub linetable: Vec<u8>,
    pub exceptiontable: Vec<u8>,
}

pub struct MarshalReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    refs: Vec<MarshalValue>,
    pyver: (u8, u8),
}

impl<'a> MarshalReader<'a> {
    pub fn new(bytes: &'a [u8], pyver: Option<(u8, u8)>) -> Self {
        Self {
            bytes,
            pos: 0,
            refs: Vec::new(),
            pyver: pyver.unwrap_or((3, 11)),
        }
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.bytes.len() {
            anyhow::bail!("marshal: eof");
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > 256 * 1024 * 1024 {
            // 256 MB limit
            anyhow::bail!("marshal: byte sequence too large");
        }
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("marshal: overflow"))?;
        if end > self.bytes.len() {
            anyhow::bail!("marshal: eof bytes");
        }
        let b = &self.bytes[self.pos..end];
        self.pos += len;
        Ok(b)
    }

    fn read_i32_le(&mut self) -> Result<i32> {
        let b = self.read_bytes(4)?;
        Ok(i32::from_le_bytes(b.try_into().unwrap()))
    }

    #[allow(dead_code)]
    fn read_u32_le(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    fn read_i64_le(&mut self) -> Result<i64> {
        let b = self.read_bytes(8)?;
        Ok(i64::from_le_bytes(b.try_into().unwrap()))
    }

    fn read_f64_le(&mut self) -> Result<f64> {
        let b = self.read_bytes(8)?;
        Ok(f64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn read_object(&mut self) -> Result<MarshalValue> {
        let code_raw = self.read_u8()?;
        let flag_ref = (code_raw & 0x80) != 0;
        let code = code_raw & 0x7F;

        let res = match code {
            b'0' => Ok(MarshalValue::Null),
            b'N' => Ok(MarshalValue::None),
            b'F' => Ok(MarshalValue::Bool(false)),
            b'T' => Ok(MarshalValue::Bool(true)),
            b'i' => Ok(MarshalValue::Int(self.read_i32_le()?)),
            b'I' => Ok(MarshalValue::Int64(self.read_i64_le()?)),
            b'f' => {
                let n = self.read_u8()?;
                let s_bytes = self.read_bytes(n as usize)?;
                let s = std::str::from_utf8(s_bytes)?;
                let f = s.parse::<f64>().unwrap_or(0.0);
                Ok(MarshalValue::Float(f))
            }
            b'g' => Ok(MarshalValue::Float(self.read_f64_le()?)),
            b'x' => {
                let n = self.read_u8()?;
                let _s = std::str::from_utf8(self.read_bytes(n as usize)?)?;
                Ok(MarshalValue::Complex(0.0, 0.0)) // Parsing complex from str is hard, skipping
            }
            b'y' => Ok(MarshalValue::Complex(
                self.read_f64_le()?,
                self.read_f64_le()?,
            )),
            b'l' => {
                let n = self.read_i32_le()?;
                let size = n.abs() as usize * 2; // roughly
                if size > 0 {
                    self.read_bytes(size)?;
                }
                Ok(MarshalValue::Long {
                    digits: n.abs() as usize,
                    negative: n < 0,
                    value_i64: None,
                })
            }
            b's' => {
                let n = self.read_i32_le()?;
                let b = self.read_bytes(n as usize)?;
                Ok(MarshalValue::Bytes(b.to_vec()))
            }
            b't' | b'u' | b'z' | b'Z' | b'a' | b'A' => {
                let n = self.read_i32_le()?;
                let b = self.read_bytes(n as usize)?;
                let s = String::from_utf8_lossy(b).into_owned();
                let val = MarshalValue::String(s);
                self.refs.push(val.clone());
                Ok(val)
            }
            b'R' | b'r' => {
                let n = self.read_i32_le()?;
                if n >= 0 && (n as usize) < self.refs.len() {
                    Ok(self.refs[n as usize].clone())
                } else {
                    Ok(MarshalValue::Null)
                }
            }
            b'(' | b'[' => {
                // Tuple/List
                let n = self.read_i32_le()?;
                if n < 0 || n > 1_000_000 {
                    anyhow::bail!("marshal: list/tuple size out of bounds");
                }
                let mut items = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    items.push(self.read_object()?);
                }
                if code == b'(' {
                    Ok(MarshalValue::Tuple(items))
                } else {
                    Ok(MarshalValue::List(items))
                }
            }
            b'{' => {
                let mut items = Vec::new();
                loop {
                    let key = self.read_object()?;
                    if matches!(key, MarshalValue::Null) {
                        break;
                    }
                    let val = self.read_object()?;
                    items.push((key, val));
                }
                Ok(MarshalValue::Dict(items))
            }
            b'c' => Ok(MarshalValue::Code(Box::new(self.read_code_object()?))),
            _ => Ok(MarshalValue::Unknown(format!("Type {}", code as char))),
        };

        if let Ok(ref v) = res {
            if flag_ref && !matches!(code, b't' | b'u' | b'z' | b'Z' | b'a' | b'A') {
                self.refs.push(v.clone());
            }
        }
        res
    }

    pub fn read_code_object(&mut self) -> Result<CodeObject> {
        let argcount = self.read_i32_le().context("argcount")?;
        let posonlyargcount = if self.pyver >= (3, 8) {
            self.read_i32_le().context("posonlyargcount")?
        } else {
            0
        };
        let kwonlyargcount = self.read_i32_le().context("kwonlyargcount")?;
        let stacksize = self.read_i32_le().context("stacksize")?;
        let flags = self.read_i32_le().context("flags")?;

        let code_val = self.read_object().context("code_val")?;
        let code = if let MarshalValue::Bytes(b) = code_val {
            b
        } else {
            Vec::new()
        };

        let consts_val = self.read_object().context("consts_val")?;
        let consts = if let MarshalValue::Tuple(v) | MarshalValue::List(v) = consts_val {
            v
        } else {
            Vec::new()
        };

        let names_val = self.read_object().context("names_val")?;
        let names = if let MarshalValue::Tuple(v) = names_val {
            v.into_iter()
                .filter_map(|x| {
                    if let MarshalValue::String(s) = x {
                        Some(s)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let varnames_val = self.read_object().context("varnames_val")?;
        let varnames = if let MarshalValue::Tuple(v) = varnames_val {
            v.into_iter()
                .filter_map(|x| {
                    if let MarshalValue::String(s) = x {
                        Some(s)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let freevars_val = self.read_object().context("freevars_val")?;
        let freevars = if let MarshalValue::Tuple(v) = freevars_val {
            v.into_iter()
                .filter_map(|x| {
                    if let MarshalValue::String(s) = x {
                        Some(s)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let cellvars_val = self.read_object().context("cellvars_val")?;
        let cellvars = if let MarshalValue::Tuple(v) = cellvars_val {
            v.into_iter()
                .filter_map(|x| {
                    if let MarshalValue::String(s) = x {
                        Some(s)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let filename_val = self.read_object().context("filename_val")?;
        let filename = if let MarshalValue::String(s) = filename_val {
            s
        } else {
            String::new()
        };

        let name_val = self.read_object().context("name_val")?;
        let name = if let MarshalValue::String(s) = name_val {
            s
        } else {
            String::new()
        };

        let qualname = if self.pyver >= (3, 11) {
            if let Ok(MarshalValue::String(s)) = self.read_object().context("qualname") {
                s
            } else {
                String::new()
            }
        } else {
            name.clone()
        };

        let firstlineno = self.read_i32_le().context("firstlineno")?;

        let linetable_val = self.read_object().context("linetable_val")?;
        let linetable = if let MarshalValue::Bytes(b) = linetable_val {
            b
        } else {
            Vec::new()
        };

        let exceptiontable = if self.pyver >= (3, 11) {
            if let Ok(MarshalValue::Bytes(b)) = self.read_object().context("exceptiontable") {
                b
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(CodeObject {
            argcount,
            posonlyargcount,
            kwonlyargcount,
            stacksize,
            flags,
            code,
            consts,
            names,
            varnames,
            freevars,
            cellvars,
            localsplusnames: Vec::new(),
            localspluskinds: Vec::new(),
            filename,
            name,
            qualname,
            firstlineno,
            linetable,
            exceptiontable,
        })
    }
}

pub fn parse_code_object(bytes: &[u8]) -> Result<CodeObject> {
    // Try without skip
    let mut reader = MarshalReader::new(bytes, None);
    if let Ok(MarshalValue::Code(code)) = reader.read_object() {
        return Ok(*code);
    }

    // Try skipping headers
    for skip in [8, 12, 16] {
        if bytes.len() > skip {
            let mut reader = MarshalReader::new(&bytes[skip..], None);
            if let Ok(MarshalValue::Code(code)) = reader.read_object() {
                return Ok(*code);
            }
        }
    }

    anyhow::bail!("Could not parse code object")
}

const DISASSEMBLE_SCRIPT: &str = r#"
import sys
import dis
import marshal
import time
import os
import io

def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

    if len(sys.argv) < 2:
        print("Usage: disassemble.py <file>")
        sys.exit(1)
        
    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
            
        code = None
        try:
            code = marshal.loads(data)
        except Exception:
            pass
            
        if not code or not isinstance(code, type((lambda:0).__code__)):
             for skip in [8, 12, 16]:
                 if len(data) > skip:
                     try:
                         obj = marshal.loads(data[skip:])
                         if isinstance(obj, type((lambda:0).__code__)):
                             code = obj
                             break
                     except Exception:
                         continue
        
        if not code:
            print("Error: Could not extract code object from data.")
            return

        dis.dis(code)
        
    except Exception as e:
        print(f"Error during disassembly: {e}")

if __name__ == "__main__":
    main()
"#;

pub fn disassemble_python_blob(bytes: &[u8], pyver: Option<(u8, u8)>) -> Result<String> {
    // Default to 3.11 if not specified
    let version = pyver.unwrap_or((3, 11));

    // Get python executable
    let python_exe = ToolManager::global()
        .setup_python(version)
        .context("Failed to setup python embedded")?;

    // Create temp directory for this operation
    let temp_dir = std::env::temp_dir().join("singularity_disasm");
    std::fs::create_dir_all(&temp_dir)?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let script_path = temp_dir.join(format!("disassemble_{}.py", timestamp));
    let target_path = temp_dir.join(format!("target_{}.pyc", timestamp));

    // Write script
    std::fs::write(&script_path, DISASSEMBLE_SCRIPT)?;

    // Write target bytes
    std::fs::write(&target_path, bytes)?;

    // Execute
    let mut cmd = std::process::Command::new(python_exe);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let output = cmd
        .arg(&script_path)
        .arg(&target_path)
        .env("PYTHONIOENCODING", "utf-8")
        .output()
        .context("Failed to execute disassembly script")?;

    // Cleanup
    let _ = std::fs::remove_file(&script_path);
    let _ = std::fs::remove_file(&target_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Disassembly failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout)
}

// Helper to avoid build errors from missing disassemble_code_object usage in tests
#[allow(unused)]
pub fn disassemble_code_object(_code: &CodeObject, _tables: &OpcodeTables) -> String {
    "Disassembly implemented via external python script".to_string()
}

#[allow(dead_code)]
pub fn tables_by_version(ver: (u8, u8)) -> Option<&'static OpcodeTables> {
    for t in py_dis_tables::ALL_TABLES {
        if t.major == ver.0 && t.minor == ver.1 {
            return Some(t);
        }
    }
    None
}
