// Copyright 2021, Benjamin Ludewig
// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate bindgen;
extern crate cmake;

use std::env;
use std::path::PathBuf;

fn main() {
    let mut builder = bindgen::Builder::default();

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
        .whitelist_function("uci_add_delta_path")
        .whitelist_function("uci_add_list")
        .whitelist_function("uci_add_section")
        .whitelist_function("uci_alloc_context")
        .whitelist_type("uci_backend")
        .whitelist_type("uci_command")
        .whitelist_function("uci_commit")
        .whitelist_type("uci_context")
        .whitelist_function("uci_del_list")
        .whitelist_function("uci_delete")
        .whitelist_type("uci_delta")
        .whitelist_type("uci_element")
        .whitelist_function("uci_export")
        .whitelist_type("uci_flags")
        .whitelist_function("uci_free_context")
        .whitelist_function("uci_get_errorstr")
        .whitelist_function("uci_hash_options")
        .whitelist_function("uci_import")
        .whitelist_type("uci_list")
        .whitelist_function("uci_list_configs")
        .whitelist_function("uci_load")
        .whitelist_function("uci_lookup_next")
        .whitelist_function("uci_lookup_ptr")
        .whitelist_type("uci_option")
        .whitelist_type("uci_option_type")
        .whitelist_type("uci_package")
        .whitelist_function("uci_parse_argument")
        .whitelist_function("uci_parse_context")
        .whitelist_function("uci_validate_text")
        .whitelist_var("UCI_OK")
        .whitelist_function("uci_parse_option")
        .whitelist_function("uci_parse_ptr")
        .whitelist_function("uci_parse_section")
        .whitelist_function("uci_perror")
        .whitelist_type("uci_ptr")
        .whitelist_function("uci_rename")
        .whitelist_function("uci_reorder_section")
        .whitelist_function("uci_revert")
        .whitelist_function("uci_save")
        .whitelist_type("uci_section")
        .whitelist_function("uci_set")
        .whitelist_function("uci_set_backend")
        .whitelist_function("uci_set_confdir")
        .whitelist_function("uci_set_savedir")
        .whitelist_type("uci_type")
        .whitelist_var("uci_type_UCI_TYPE_OPTION")
        .whitelist_function("uci_unload")
        .no_debug("uci_ptr")
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
