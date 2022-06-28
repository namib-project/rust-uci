// Copyright 2021, Benjamin Ludewig
// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate bindgen;
extern crate cmake;

use std::{env, fs};
use std::path::PathBuf;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");

    // don't run cmake if running for docs.rs
    if let Ok(_) = env::var("DOCS_RS") {
        fs::copy("generated/bindings.rs", out_path).unwrap();
        return;
    }

    let mut builder = bindgen::Builder::default();
    // if BINDGEN_TARGET is set it instructs the target bindgen is built for
    if let Ok(bindgen_target) = env::var("BINDGEN_TARGET") {
        builder = builder.clang_arg(format!("--target={}", bindgen_target));
    }

    // if UCI_DIR is present, use it to look for the header file and precompiled libs
    if let Ok(uci_dir) = env::var("UCI_DIR") {
        println!("cargo:rustc-link-search=native={}/lib", uci_dir);
        builder = builder.clang_arg(format!("-I{}/include", uci_dir));
    } else {
        // otherwise build it from source
        let libubox = cmake::Config::new("libubox")
            .define("BUILD_LUA", "OFF")
            .define("BUILD_EXAMPLES", "OFF")
            .build();
        let libuci = cmake::Config::new("uci")
            .define("BUILD_LUA", "OFF")
            .define("BUILD_STATIC", "OFF")
            .define(
                "ubox_include_dir",
                libubox.join("include").as_path().display().to_string(),
            )
            .build();
        println!("cargo:rustc-link-search=native={}/lib", libuci.display());
        builder = builder.clang_arg(format!("-I{}/include", libuci.display()))
    }

    // Link to libuci and libubox
    println!("cargo:rustc-link-lib=dylib=uci");
    println!("cargo:rustc-link-lib=dylib=ubox");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = builder
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .allowlist_function("uci_.*")
        .allowlist_type("uci_.*")
        .allowlist_var("uci_.*")
        .allowlist_var("UCI_.*")
        .no_debug("uci_ptr")
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
