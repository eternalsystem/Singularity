use aes::Aes256;
use base64::{Engine as _, engine::general_purpose};
use boa_engine::{
    Context, JsString, JsValue, NativeFunction, Source, object::ObjectInitializer,
    property::Attribute,
};
use boa_gc::{Finalize, Trace};
use cbc::Decryptor;
use cbc::cipher::{
    BlockDecryptMut, KeyIvInit,
    block_padding::{NoPadding, Pkcs7},
};
use hex;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Sha256, Sha512};
use std::cell::RefCell;
use std::fs::File;
use std::io::Write;
use std::rc::Rc;

type Aes256CbcDec = Decryptor<Aes256>;

#[derive(Clone, Finalize)]
struct LogInternal(Rc<RefCell<Vec<String>>>);

unsafe impl Trace for LogInternal {
    unsafe fn trace(&self, _tracer: &mut boa_gc::Tracer) {}
    unsafe fn trace_non_roots(&self) {}
    fn run_finalizer(&self) {
        boa_gc::Finalize::finalize(self);
    }
}

// Helper functions for Buffer and Crypto
fn get_bytes(val: &JsValue, ctx: &mut Context) -> Vec<u8> {
    if let Some(obj) = val.as_object() {
        if let Ok(internal) = obj.get(JsString::from("__internal_data"), ctx) {
            if let Some(s) = internal.as_string() {
                if let Ok(bytes) = general_purpose::STANDARD.decode(s.to_std_string_escaped()) {
                    return bytes;
                }
            }
        }
    }
    if let Ok(s) = val.to_string(ctx) {
        return s.to_std_string_escaped().into_bytes();
    }
    Vec::new()
}

fn create_buffer(ctx: &mut Context, bytes: Vec<u8>) -> JsValue {
    let base64_data = general_purpose::STANDARD.encode(&bytes);
    let bytes_clone = bytes.clone();

    let buf_obj = ObjectInitializer::new(ctx)
        .property(
            JsString::from("__internal_data"),
            JsString::from(base64_data),
            Attribute::all(),
        )
        .function(
            unsafe {
                NativeFunction::from_closure(move |_this, args, _ctx| {
                    let encoding = args
                        .get(0)
                        .and_then(|v| v.as_string())
                        .map(|s| s.to_std_string_escaped())
                        .unwrap_or_else(|| "utf8".to_string());
                    if encoding == "base64" {
                        let s = general_purpose::STANDARD.encode(&bytes_clone);
                        Ok(JsValue::new(JsString::from(s)))
                    } else if encoding == "hex" {
                        let s = hex::encode(&bytes_clone);
                        Ok(JsValue::new(JsString::from(s)))
                    } else {
                        let s = String::from_utf8_lossy(&bytes_clone).to_string();
                        Ok(JsValue::new(JsString::from(s)))
                    }
                })
            },
            JsString::from("toString"),
            0,
        )
        .build();
    buf_obj.into()
}

pub struct JsSandbox {
    context: Context,
    logs: Rc<RefCell<Vec<String>>>,
}

impl JsSandbox {
    pub fn new() -> Self {
        let logs = Rc::new(RefCell::new(Vec::new()));
        let mut context = Context::default();

        // Register global 'log' function (like console.log)
        let logs_internal = LogInternal(logs.clone());
        context
            .register_global_callable(JsString::from("log"), 1, unsafe {
                NativeFunction::from_closure(move |_this, args, context| {
                    let msg = args
                        .iter()
                        .map(|a| a.to_string(context).unwrap().to_std_string_escaped())
                        .collect::<Vec<_>>()
                        .join(" ");
                    logs_internal.0.borrow_mut().push(format!("[LOG] {}", msg));
                    Ok(JsValue::undefined())
                })
            })
            .unwrap();

        // Create 'console' object
        let logs_internal = LogInternal(logs.clone());
        let console = ObjectInitializer::new(&mut context)
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, args, context| {
                        let msg = args
                            .iter()
                            .map(|a| a.to_string(context).unwrap().to_std_string_escaped())
                            .collect::<Vec<_>>()
                            .join(" ");
                        logs_internal
                            .0
                            .borrow_mut()
                            .push(format!("[CONSOLE] {}", msg));
                        Ok(JsValue::undefined())
                    })
                },
                JsString::from("log"),
                0,
            )
            .build();
        let _ =
            context.register_global_property(JsString::from("console"), console, Attribute::all());

        // --- Mock Timers (setTimeout, setInterval, etc.) ---
        let timers_mock = unsafe {
            NativeFunction::from_closure(move |_this, args, ctx| {
                let callback = args.get(0).and_then(|v| v.as_object());
                if let Some(cb) = callback {
                    if cb.is_callable() {
                        let undefined = JsValue::undefined();
                        // Execute callback immediately to simulate synchronous execution in sandbox
                        let _ = cb.call(&undefined, &[], ctx);
                    }
                }
                // Return a dummy timer ID
                Ok(JsValue::new(1))
            })
        };
        context
            .register_global_callable(JsString::from("setTimeout"), 2, timers_mock.clone())
            .unwrap();
        context
            .register_global_callable(JsString::from("setInterval"), 2, timers_mock.clone())
            .unwrap(); // Run once
        context
            .register_global_callable(JsString::from("setImmediate"), 1, timers_mock.clone())
            .unwrap();

        let clear_timer_mock = unsafe {
            NativeFunction::from_closure(move |_this, _args, _ctx| Ok(JsValue::undefined()))
        };
        context
            .register_global_callable(JsString::from("clearTimeout"), 1, clear_timer_mock.clone())
            .unwrap();
        context
            .register_global_callable(JsString::from("clearInterval"), 1, clear_timer_mock.clone())
            .unwrap();

        // --- Mock Process ---
        // Build env object first
        let env_obj = ObjectInitializer::new(&mut context)
            .property(
                JsString::from("TEMP"),
                JsString::from("C:\\Users\\Admin\\AppData\\Local\\Temp"),
                Attribute::all(),
            )
            .property(
                JsString::from("APPDATA"),
                JsString::from("C:\\Users\\Admin\\AppData\\Roaming"),
                Attribute::all(),
            )
            .property(
                JsString::from("COMPUTERNAME"),
                JsString::from("DESKTOP-USER"),
                Attribute::all(),
            )
            .property(
                JsString::from("USERNAME"),
                JsString::from("Admin"),
                Attribute::all(),
            )
            .build();

        // Build versions object
        let versions_obj = ObjectInitializer::new(&mut context)
            .property(
                JsString::from("node"),
                JsString::from("14.17.0"),
                Attribute::all(),
            )
            .build();

        let process_obj = ObjectInitializer::new(&mut context)
            .property(
                JsString::from("platform"),
                JsString::from("win32"),
                Attribute::all(),
            )
            .property(
                JsString::from("arch"),
                JsString::from("x64"),
                Attribute::all(),
            )
            .property(JsString::from("env"), env_obj, Attribute::all())
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, _args, _ctx| {
                        Ok(JsValue::new(JsString::from("C:\\Users\\Admin\\Downloads")))
                    })
                },
                JsString::from("cwd"),
                0,
            )
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, _args, _ctx| Ok(JsValue::undefined()))
                },
                JsString::from("exit"),
                1,
            )
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, _args, _ctx| {
                        Ok(JsValue::new(JsString::from("v14.17.0")))
                    })
                },
                JsString::from("version"),
                0,
            )
            .property(JsString::from("versions"), versions_obj, Attribute::all())
            .build();

        let _ = context.register_global_property(
            JsString::from("process"),
            process_obj,
            Attribute::all(),
        );

        // --- Mock Global ---
        let global_obj = context.global_object();
        let _ = context.register_global_property(
            JsString::from("global"),
            global_obj,
            Attribute::all(),
        );

        // --- Mock Buffer ---
        let buffer_from = unsafe {
            NativeFunction::from_closure(move |_this, args, ctx| {
                let value_arg = args.get(0);
                let encoding_arg = args.get(1);

                let mut bytes = Vec::new();

                if let Some(val) = value_arg {
                    if let Ok(s_js) = val.to_string(ctx) {
                        let s = s_js.to_std_string_escaped();
                        let encoding = encoding_arg
                            .and_then(|v| v.as_string())
                            .map(|s| s.to_std_string_escaped())
                            .unwrap_or_else(|| "utf8".to_string());

                        if encoding == "base64" {
                            if let Ok(decoded) = general_purpose::STANDARD.decode(&s) {
                                bytes = decoded;
                            } else {
                                bytes = s.into_bytes();
                            }
                        } else if encoding == "hex" {
                            if let Ok(decoded) = hex::decode(&s) {
                                bytes = decoded;
                            } else {
                                bytes = s.into_bytes();
                            }
                        } else {
                            bytes = s.into_bytes();
                        }
                    }
                }

                Ok(create_buffer(ctx, bytes))
            })
        };

        let buffer_alloc = unsafe {
            NativeFunction::from_closure(move |_this, _args, ctx| Ok(create_buffer(ctx, vec![])))
        };

        let buffer_obj = ObjectInitializer::new(&mut context)
            .function(buffer_from, JsString::from("from"), 2)
            .function(buffer_alloc, JsString::from("alloc"), 1)
            .build();

        let _ = context.register_global_property(
            JsString::from("Buffer"),
            buffer_obj,
            Attribute::all(),
        );

        // --- Mock Crypto ---
        let logs_crypto = LogInternal(logs.clone());
        let logs_crypto_dec = logs_crypto.clone();
        let crypto_mock = ObjectInitializer::new(&mut context)
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, args, ctx| {
                        let password_arg = args.get(0);
                        let salt_arg = args.get(1);
                        let iterations = args.get(2).and_then(|v| v.as_number()).unwrap_or(1.0) as u32;
                        let keylen = args.get(3).and_then(|v| v.as_number()).unwrap_or(32.0) as usize;
                        let digest = args.get(4).and_then(|v| v.as_string()).map(|s| s.to_std_string_escaped()).unwrap_or_else(|| "sha1".to_string());

                        let password = get_bytes(password_arg.unwrap_or(&JsValue::undefined()), ctx);
                        let salt = get_bytes(salt_arg.unwrap_or(&JsValue::undefined()), ctx);

                        logs_crypto.0.borrow_mut().push(format!("[CRYPTO] pbkdf2Sync called. Iter: {}, Keylen: {}, Digest: {}", iterations, keylen, digest));

                        let mut key = vec![0u8; keylen];

                        match digest.as_str() {
                            "sha512" => {
                                let _ = pbkdf2::<Hmac<Sha512>>(&password, &salt, iterations, &mut key);
                            },
                             "sha256" => {
                                let _ = pbkdf2::<Hmac<Sha256>>(&password, &salt, iterations, &mut key);
                            },
                            _ => {
                                // Default or fallback
                                let _ = pbkdf2::<Hmac<Sha512>>(&password, &salt, iterations, &mut key);
                            }
                        }

                        Ok(create_buffer(ctx, key))
                    })
                },
                JsString::from("pbkdf2Sync"), 5
            )
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, args, ctx| {
                         let algorithm = args.get(0).and_then(|v| v.as_string()).map(|s| s.to_std_string_escaped()).unwrap_or_default();
                         let key_arg = args.get(1);
                         let iv_arg = args.get(2);

                         let key = get_bytes(key_arg.unwrap_or(&JsValue::undefined()), ctx);
                         let iv = get_bytes(iv_arg.unwrap_or(&JsValue::undefined()), ctx);

                         logs_crypto_dec.0.borrow_mut().push(format!("[CRYPTO] createDecipheriv called: {} (key len: {}, iv len: {})", algorithm, key.len(), iv.len()));

                         if algorithm == "aes-256-cbc" {
                             if key.len() == 32 && iv.len() == 16 {
                                 if let Ok(decryptor) = Aes256CbcDec::new_from_slices(&key, &iv) {
                                     let decryptor_rc = Rc::new(RefCell::new(Some(decryptor)));
                                     let buffer_rc = Rc::new(RefCell::new(Vec::new()));

                                    let buffer_clone1 = buffer_rc.clone();
                                    let decryptor_clone2 = decryptor_rc.clone();
                                    let buffer_clone2 = buffer_rc.clone();

                                    let logs_update = logs_crypto_dec.clone();
                                    let logs_final = logs_crypto_dec.clone();

                                    let auto_padding = Rc::new(RefCell::new(true));
                                    let auto_padding_clone = auto_padding.clone();
                                    let auto_padding_clone2 = auto_padding.clone();

                                    let decipher = ObjectInitializer::new(ctx)
                                       .function(
                                           NativeFunction::from_closure(move |_this, args, ctx| {
                                               let undefined = JsValue::undefined();
                                               let val = args.get(0).unwrap_or(&undefined);
                                               let encoding = args.get(1).and_then(|v| v.as_string()).map(|s| s.to_std_string_escaped());

                                               let mut data = Vec::new();

                                               // Check if it's a Buffer (Mocked)
                                               let is_buffer = val.as_object()
                                                   .and_then(|obj| obj.get(JsString::from("__internal_data"), ctx).ok())
                                                   .is_some();

                                               if is_buffer {
                                                   data = get_bytes(val, ctx);
                                               } else {
                                                   // Treat as string
                                                   if let Ok(s_js) = val.to_string(ctx) {
                                                       let s = s_js.to_std_string_escaped();
                                                       match encoding.as_deref() {
                                                           Some("base64") => {
                                                               if let Ok(decoded) = general_purpose::STANDARD.decode(&s) {
                                                                   data = decoded;
                                                               } else {
                                                                   data = s.into_bytes();
                                                               }
                                                           },
                                                           Some("hex") => {
                                                               if let Ok(decoded) = hex::decode(&s) {
                                                                   data = decoded;
                                                               } else {
                                                                   data = s.into_bytes();
                                                               }
                                                           },
                                                           _ => {
                                                               data = s.into_bytes();
                                                           }
                                                       }
                                                   }
                                               }

                                               logs_update.0.borrow_mut().push(format!("[CRYPTO] update called with {} bytes (encoding: {:?})", data.len(), encoding));
                                               buffer_clone1.borrow_mut().extend(data);
                                               // Return empty buffer
                                               Ok(create_buffer(ctx, vec![]))
                                           }),
                                           JsString::from("update"), 2
                                       )
                                       .function(
                                            NativeFunction::from_closure(move |_this, args, _ctx| {
                                                let val = args.get(0).and_then(|v| v.as_boolean()).unwrap_or(true);
                                                *auto_padding_clone.borrow_mut() = val;
                                                Ok(_this.clone())
                                            }),
                                            JsString::from("setAutoPadding"), 1
                                       )
                                       .function(
                                           NativeFunction::from_closure(move |_this, _args, _ctx| {
                                                logs_final.0.borrow_mut().push(format!("[CRYPTO] final called"));
                                                let mut buf = buffer_clone2.borrow_mut();
                                                let padding = *auto_padding_clone2.borrow();

                                                if let Some(dec) = decryptor_clone2.borrow_mut().take() {
                                                    let res = if padding {
                                                        dec.decrypt_padded_mut::<Pkcs7>(&mut buf).map(|b| b.to_vec())
                                                    } else {
                                                        dec.decrypt_padded_mut::<NoPadding>(&mut buf).map(|b| b.to_vec())
                                                    };

                                                    if let Ok(plaintext) = res {
                                                         let preview_len = std::cmp::min(100, plaintext.len());
                                                         let preview = String::from_utf8_lossy(&plaintext[..preview_len]).to_string();
                                                         logs_final.0.borrow_mut().push(format!("[CRYPTO] Decrypted content preview (first 100 chars): {}", preview));

                                                         // Dump decrypted payload to file immediately
                                                          if let Ok(mut file) = File::create("decrypted_payload.js") {
                                                              let _ = file.write_all(&plaintext);
                                                              let _ = file.flush();
                                                              println!("[CRYPTO] Payload saved to decrypted_payload.js");
                                                              logs_final.0.borrow_mut().push(format!("[CRYPTO] Payload saved to decrypted_payload.js"));
                                                          }

                                                          // Return neutralized payload to avoid engine crash on complex obfuscated code
                                                          // The user can inspect the actual payload in the file.
                                                          let neutralized = "console.log('Malware payload captured and neutralized.');";
                                                          return Ok(JsValue::new(JsString::from(neutralized)));
                                                     } else {
                                                         logs_final.0.borrow_mut().push(format!("[CRYPTO] Decryption failed (padding error?)"));
                                                    }
                                                }
                                                Ok(JsValue::undefined())
                                           }),
                                           JsString::from("final"), 1
                                       )
                                       .build();

                                     return Ok(decipher.into());
                                 }
                             }
                         }

                         // Fallback
                         Ok(JsValue::undefined())
                    })
                },
                JsString::from("createDecipheriv"), 3
            )
            .build();

        // --- Generic Mocking System (Proxy) ---
        let logs_mock = LogInternal(logs.clone());
        context
            .register_global_callable(JsString::from("__log_mock_action"), 2, unsafe {
                NativeFunction::from_closure(move |_this, args, _context| {
                    let action = args
                        .get(0)
                        .and_then(|v| v.as_string())
                        .map(|s| s.to_std_string_escaped())
                        .unwrap_or_default();
                    let details = args
                        .get(1)
                        .and_then(|v| v.as_string())
                        .map(|s| s.to_std_string_escaped())
                        .unwrap_or_default();
                    logs_mock
                        .0
                        .borrow_mut()
                        .push(format!("[MOCK] {} {}", action, details));
                    Ok(JsValue::undefined())
                })
            })
            .unwrap();

        let mock_helper_script = r#"
            function __createMock(name) {
                // Return a function that acts as both object and callable
                const proxy = new Proxy(function() {}, {
                    get: function(target, prop, receiver) {
                        // Primitive conversions to prevent logic errors
                        if (prop === Symbol.toPrimitive || prop === "valueOf") {
                            return function() { return 1; }; // Act as 'true' or number 1
                        }
                        if (prop === "toString") {
                            return function() { return "[MockObject " + name + "]"; };
                        }
                        if (prop === "then") {
                            // Act as a Promise that resolves immediately
                            return function(resolve) { if(resolve) resolve(__createMock(name + ".then")); };
                        }
                        if (prop === "prototype" || prop === "constructor") {
                            return Reflect.get(target, prop, receiver);
                        }
                        // Default: return a new mock
                        return __createMock(name + "." + String(prop));
                    },
                    apply: function(target, thisArg, argumentsList) {
                        var args = [];
                        var callback = null;
                        for (var i = 0; i < argumentsList.length; i++) {
                            var arg = argumentsList[i];
                            try {
                                if (typeof arg === 'function') {
                                    callback = arg;
                                    args.push("[Function]");
                                } else {
                                    args.push(String(arg));
                                }
                            } catch (e) {
                                args.push("?");
                            }
                        }

                        __log_mock_action(name + " called with:", args.join(", "));

                        // HEURISTIC: Auto-execute callback if found
                         // Most Node callbacks are (error, result) or (error, stdout, stderr)
                         if (callback) {
                             try {
                                 // Simulate async success
                                 // We pass (null, "generic_success", "") to satisfy common patterns
                                 const mockRes = "Simulated output for " + name;
                                 callback(null, mockRes, "");
                             } catch (e) {
                                 __log_mock_action("Error executing callback for " + name, String(e));
                             }
                         }
 
                         // Return a new mock for chaining
                        return __createMock(name + "_result");
                    },
                    construct: function(target, argumentsList, newTarget) {
                        __log_mock_action("new " + name + " constructed", "");
                        return __createMock("new " + name);
                    }
                });
                return proxy;
            }

            function __createChildProcessMock(stdoutStr, stderrStr) {
                var mock = {
                    stdout: {
                        on: function(event, cb) {
                            if (event === 'data' && typeof cb === 'function') {
                                try { cb(stdoutStr); } catch(e) { __log_mock_action("Error in stdout data callback", String(e)); }
                            }
                            return this;
                        },
                        pipe: function() { return this; }
                    },
                    stderr: {
                        on: function(event, cb) {
                            if (event === 'data' && typeof cb === 'function') {
                                try { cb(stderrStr); } catch(e) { __log_mock_action("Error in stderr data callback", String(e)); }
                            }
                            return this;
                        }
                    },
                    on: function(event, cb) {
                        if ((event === 'exit' || event === 'close') && typeof cb === 'function') {
                            try { cb(0); } catch(e) { __log_mock_action("Error in process exit callback", String(e)); }
                        }
                        return this;
                    },
                    unref: function() {},
                    kill: function() {},
                    pid: 1234,
                    stdin: { write: function() {}, end: function() {} }
                };
                return mock;
            }
        "#;
        context
            .eval(Source::from_bytes(mock_helper_script))
            .unwrap();

        // Setup the 'require' mock system

        // --- Mock FS ---
        let logs_fs = LogInternal(logs.clone());
        let logs_fs_read = logs_fs.clone();

        let fs_mock = ObjectInitializer::new(&mut context)
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, args, _ctx| {
                        let path = args
                            .get(0)
                            .and_then(|v| v.as_string())
                            .map(|s| s.to_std_string_escaped())
                            .unwrap_or_default();
                        logs_fs
                            .0
                            .borrow_mut()
                            .push(format!("[FS] writeFileSync called on: {}", path));
                        Ok(JsValue::undefined())
                    })
                },
                JsString::from("writeFileSync"),
                2,
            )
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, args, _ctx| {
                        let path = args
                            .get(0)
                            .and_then(|v| v.as_string())
                            .map(|s| s.to_std_string_escaped())
                            .unwrap_or_default();
                        logs_fs_read
                            .0
                            .borrow_mut()
                            .push(format!("[FS] readFile called on: {}", path));

                        // Call callback if present (usually last arg)
                        let callback = args.iter().rev().find(|arg| arg.is_callable());
                        if let Some(cb) = callback {
                            let cb_obj = cb.as_object().unwrap();
                            let undefined = JsValue::undefined();
                            let null = JsValue::null();
                            let data = JsValue::new(JsString::from("Simulated file content"));
                            let _ = cb_obj.call(&undefined, &[null, data], _ctx);
                        }

                        Ok(JsValue::new(JsString::from("mock_content")))
                    })
                },
                JsString::from("readFile"),
                2,
            )
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, _args, _ctx| {
                        // existsSync always returns true
                        Ok(JsValue::new(true))
                    })
                },
                JsString::from("existsSync"),
                1,
            )
            .build();

        // --- Mock Child Process ---
        let logs_cp = LogInternal(logs.clone());
        let logs_cp_exec = logs_cp.clone();
        let logs_cp_spawn = logs_cp.clone();

        let cp_mock = ObjectInitializer::new(&mut context)
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, args, ctx| {
                        let cmd = args.get(0).and_then(|v| v.as_string()).map(|s| s.to_std_string_escaped()).unwrap_or_default();

                        // Detailed arg logging
                        let arg_types: Vec<String> = args.iter().map(|a| a.type_of().to_string()).collect();
                        logs_cp_exec.0.borrow_mut().push(format!("[CMD] exec called: {} (args: {:?})", cmd, arg_types));

                        // Check for callback (usually the last argument)
                        let callback = args.iter().rev().find(|arg| arg.is_callable());

                        // Fake stdout based on command
                        let stdout_str = if cmd.to_lowercase().contains("tasklist") {
                            "\nImage Name                     PID Session Name        Session#    Mem Usage\n========================= ======== ================ =========== ============\nSystem Idle Process              0 Services                   0          8 K\nSystem                           4 Services                   0      2,344 K\nexplorer.exe                  6892 Console                    1    236,240 K\nchrome.exe                    1234 Console                    1    150,000 K\n"
                        } else if cmd.to_lowercase().contains("ipify") {
                            "194.250.231.149"
                        } else {
                            "Command executed successfully. Simulated Output."
                        };

                        if let Some(cb) = callback {
                            let cb_obj = cb.as_object().unwrap();
                            let undefined = JsValue::undefined();
                            let null = JsValue::null();

                            let stdout = JsValue::new(JsString::from(stdout_str));
                            let stderr = JsValue::new(JsString::from(""));

                            logs_cp_exec.0.borrow_mut().push(format!("[CMD] Triggering callback for: {}", cmd));
                            if let Err(e) = cb_obj.call(&undefined, &[null, stdout, stderr], ctx) {
                                logs_cp_exec.0.borrow_mut().push(format!("[CMD] Callback threw error: {}", e));
                            }
                        }

                        // Return a ChildProcess Mock (always)
                        let global = ctx.global_object();
                        let create_cp_mock = global.get(JsString::from("__createChildProcessMock"), ctx).unwrap();
                        let args_mock = [
                            JsValue::new(JsString::from(stdout_str)),
                            JsValue::new(JsString::from(""))
                        ];

                        if let Some(obj) = create_cp_mock.as_object() {
                            if let Ok(res) = obj.call(&JsValue::undefined(), &args_mock, ctx) {
                                return Ok(res);
                            }
                        }

                        Ok(JsValue::undefined())
                    })
                },
                JsString::from("exec"), 1
            )
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, args, ctx| {
                        let cmd = args.get(0).and_then(|v| v.as_string()).map(|s| s.to_std_string_escaped()).unwrap_or_default();
                        logs_cp_spawn.0.borrow_mut().push(format!("[CMD] spawn called: {}", cmd));

                        // Fake stdout based on command
                        let stdout_str = if cmd.to_lowercase().contains("tasklist") {
                            "\nImage Name                     PID Session Name        Session#    Mem Usage\n========================= ======== ================ =========== ============\nSystem Idle Process              0 Services                   0          8 K\nSystem                           4 Services                   0      2,344 K\nexplorer.exe                  6892 Console                    1    236,240 K\nchrome.exe                    1234 Console                    1    150,000 K\n"
                        } else if cmd.to_lowercase().contains("ipify") {
                            "194.250.231.149"
                        } else {
                            "Command executed successfully. Simulated Output."
                        };

                        // Return a ChildProcess Mock
                        let global = ctx.global_object();
                        let create_cp_mock = global.get(JsString::from("__createChildProcessMock"), ctx).unwrap();
                        let args_mock = [
                            JsValue::new(JsString::from(stdout_str)),
                            JsValue::new(JsString::from(""))
                        ];

                        if let Some(obj) = create_cp_mock.as_object() {
                            if let Ok(res) = obj.call(&JsValue::undefined(), &args_mock, ctx) {
                                return Ok(res);
                            }
                        }
                        Ok(JsValue::undefined())
                    })
                },
                JsString::from("spawn"), 1
            )
            .build();

        // --- Mock OS ---
        let logs_os = LogInternal(logs.clone());
        let logs_os_tmp = logs_os.clone();
        let logs_os_plat = logs_os.clone();
        let logs_os_type = logs_os.clone();
        let logs_os_home = logs_os.clone();

        let os_mock = ObjectInitializer::new(&mut context)
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, _args, _ctx| {
                        logs_os_tmp
                            .0
                            .borrow_mut()
                            .push("[OS] tmpdir called".to_string());
                        Ok(JsValue::new(JsString::from(
                            "C:\\Users\\Admin\\AppData\\Local\\Temp",
                        )))
                    })
                },
                JsString::from("tmpdir"),
                0,
            )
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, _args, _ctx| {
                        logs_os_plat
                            .0
                            .borrow_mut()
                            .push("[OS] platform called".to_string());
                        Ok(JsValue::new(JsString::from("win32")))
                    })
                },
                JsString::from("platform"),
                0,
            )
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, _args, _ctx| {
                        logs_os_type
                            .0
                            .borrow_mut()
                            .push("[OS] type called".to_string());
                        Ok(JsValue::new(JsString::from("Windows_NT")))
                    })
                },
                JsString::from("type"),
                0,
            )
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, _args, _ctx| {
                        logs_os_home
                            .0
                            .borrow_mut()
                            .push("[OS] homedir called".to_string());
                        Ok(JsValue::new(JsString::from("C:\\Users\\Admin")))
                    })
                },
                JsString::from("homedir"),
                0,
            )
            .build();

        // --- Mock Path ---
        let logs_path = LogInternal(logs.clone());
        let logs_path_join = logs_path.clone();
        let logs_path_resolve = logs_path.clone();

        let path_mock = ObjectInitializer::new(&mut context)
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, args, ctx| {
                        let parts: Vec<String> = args
                            .iter()
                            .map(|v| v.to_string(ctx).unwrap().to_std_string_escaped())
                            .collect();
                        logs_path_join
                            .0
                            .borrow_mut()
                            .push(format!("[PATH] join called with {:?}", parts));
                        Ok(JsValue::new(JsString::from(parts.join("\\"))))
                    })
                },
                JsString::from("join"),
                1,
            )
            .function(
                unsafe {
                    NativeFunction::from_closure(move |_this, args, ctx| {
                        let path = args
                            .get(0)
                            .and_then(|v| v.to_string(ctx).ok())
                            .map(|s| s.to_std_string_escaped())
                            .unwrap_or_default();
                        logs_path_resolve
                            .0
                            .borrow_mut()
                            .push(format!("[PATH] resolve called with {}", path));
                        Ok(JsValue::new(JsString::from(format!(
                            "C:\\Users\\Admin\\{}",
                            path
                        ))))
                    })
                },
                JsString::from("resolve"),
                1,
            )
            .build();

        // --- Mock Require Function ---
        let logs_for_require = LogInternal(logs.clone());
        let require_fn = unsafe {
            NativeFunction::from_closure(move |_this, args, ctx| {
                let module_name = args
                    .get(0)
                    .and_then(|v| v.as_string())
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();
                logs_for_require
                    .0
                    .borrow_mut()
                    .push(format!("[REQUIRE] Loading module: {}", module_name));

                if module_name == "fs" || module_name == "fs-extra" {
                    return Ok(fs_mock.clone().into());
                }
                if module_name == "child_process" {
                    return Ok(cp_mock.clone().into());
                }
                if module_name == "crypto" {
                    return Ok(crypto_mock.clone().into());
                }
                if module_name == "os" {
                    return Ok(os_mock.clone().into());
                }
                if module_name == "path" {
                    return Ok(path_mock.clone().into());
                }
                if module_name == "buffer" {
                    let global = ctx.global_object();
                    let buf = global
                        .get(JsString::from("Buffer"), ctx)
                        .unwrap_or_default();
                    let export = ObjectInitializer::new(ctx)
                        .property(JsString::from("Buffer"), buf, Attribute::all())
                        .build();
                    return Ok(export.into());
                }

                // Return a Universal Mock for unknown modules
                let global = ctx.global_object();
                let create_mock_fn = global.get(JsString::from("__createMock"), ctx).unwrap();
                let mock_name = JsValue::new(JsString::from(module_name.clone()));

                if let Some(obj) = create_mock_fn.as_object() {
                    if let Ok(res) = obj.call(&JsValue::undefined(), &[mock_name], ctx) {
                        return Ok(res);
                    }
                }

                // Fallback
                let generic = ObjectInitializer::new(ctx).build();
                Ok(generic.into())
            })
        };

        context
            .register_global_callable(JsString::from("require"), 1, require_fn)
            .unwrap();

        Self { context, logs }
    }

    pub fn run_script(&mut self, code: &str) -> Vec<String> {
        let src = Source::from_bytes(code);
        match self.context.eval(src) {
            Ok(v) => {
                let res = v
                    .to_string(&mut self.context)
                    .unwrap()
                    .to_std_string_escaped();
                self.logs.borrow_mut().push(format!("[RESULT] {}", res));
            }
            Err(e) => {
                self.logs.borrow_mut().push(format!("[ERROR] {}", e));
            }
        }
        self.logs.borrow().clone()
    }
}
