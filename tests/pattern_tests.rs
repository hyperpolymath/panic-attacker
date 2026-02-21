// SPDX-License-Identifier: PMPL-1.0-or-later

//! Tests for new language-specific patterns added in v2.1

use panic_attack::assail;
use panic_attack::types::*;
use std::fs;
use tempfile::TempDir;

fn create_test_file(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    path
}

fn has_category(report: &AssailReport, cat: WeakPointCategory) -> bool {
    report.weak_points.iter().any(|wp| wp.category == cat)
}

// === Rust patterns ===

#[test]
fn test_rust_transmute_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
use std::mem;

fn main() {
    let x: u32 = unsafe { mem::transmute(1.0_f32) };
    println!("{}", x);
}
"#;
    let file = create_test_file(&dir, "test.rs", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::UnsafeCode),
        "transmute should be detected as UnsafeCode"
    );
}

#[test]
fn test_rust_mem_forget_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
use std::mem;

fn main() {
    let v = vec![1, 2, 3];
    mem::forget(v);
}
"#;
    let file = create_test_file(&dir, "test.rs", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::ResourceLeak),
        "mem::forget should be detected as ResourceLeak"
    );
}

#[test]
fn test_rust_raw_pointer_cast_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
fn main() {
    let x = 42;
    let ptr = &x as *const i32;
    let mptr = &x as *mut i32;
    println!("{:?}", ptr);
}
"#;
    let file = create_test_file(&dir, "test.rs", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::UnsafeCode),
        "raw pointer casts should be detected as UnsafeCode"
    );
}

// === C/C++ patterns ===

#[test]
fn test_c_gets_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
#include <stdio.h>

int main() {
    char buffer[256];
    gets(buffer);
    printf("%s\n", buffer);
    return 0;
}
"#;
    let file = create_test_file(&dir, "test.c", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::UnsafeCode),
        "gets() should be detected as UnsafeCode"
    );
}

#[test]
fn test_c_system_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
#include <stdlib.h>

int main() {
    system("ls -la");
    return 0;
}
"#;
    let file = create_test_file(&dir, "test.c", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::CommandInjection),
        "system() should be detected as CommandInjection"
    );
}

#[test]
fn test_c_sprintf_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
#include <stdio.h>

int main() {
    char buf[64];
    sprintf(buf, "hello %s", "world");
    return 0;
}
"#;
    let file = create_test_file(&dir, "test.c", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::UnsafeCode),
        "sprintf() should be detected as UnsafeCode"
    );
}

// === Go patterns ===

#[test]
fn test_go_unsafe_pointer_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
package main

import "unsafe"

func main() {
    var x int = 42
    ptr := unsafe.Pointer(&x)
    _ = ptr
}
"#;
    let file = create_test_file(&dir, "test.go", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::UnsafeCode),
        "unsafe.Pointer should be detected as UnsafeCode"
    );
}

#[test]
fn test_go_exec_command_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
package main

import "os/exec"

func main() {
    cmd := exec.Command("ls", "-la")
    cmd.Run()
}
"#;
    let file = create_test_file(&dir, "test.go", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::CommandInjection),
        "exec.Command should be detected as CommandInjection"
    );
}

// === Python patterns ===

#[test]
fn test_python_pickle_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
import pickle

with open("data.pkl", "rb") as f:
    data = pickle.load(f)
    items = pickle.loads(raw_bytes)
"#;
    let file = create_test_file(&dir, "test.py", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::UnsafeDeserialization),
        "pickle.load/loads should be detected as UnsafeDeserialization"
    );
}

#[test]
fn test_python_os_system_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
import os

os.system("rm -rf /tmp/test")
os.popen("ls")
"#;
    let file = create_test_file(&dir, "test.py", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::CommandInjection),
        "os.system/os.popen should be detected as CommandInjection"
    );
}

// === JavaScript patterns ===

#[test]
fn test_js_innerhtml_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
const el = document.getElementById("app");
el.innerHTML = "<div>" + userInput + "</div>";
document.write("<p>test</p>");
"#;
    let file = create_test_file(&dir, "test.js", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::DynamicCodeExecution),
        "innerHTML/document.write should be detected as DynamicCodeExecution"
    );
}

#[test]
fn test_js_dangerously_set_innerhtml_detection() {
    let dir = TempDir::new().unwrap();
    let content = r#"
function App() {
    return <div dangerouslySetInnerHTML={{ __html: userContent }} />;
}
"#;
    let file = create_test_file(&dir, "test.js", content);
    let report = assail::analyze(&file).expect("analysis should succeed");

    assert!(
        has_category(&report, WeakPointCategory::DynamicCodeExecution),
        "dangerouslySetInnerHTML should be detected as DynamicCodeExecution"
    );
}
