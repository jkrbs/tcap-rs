use std::process::Command;

// read compiled git commit hash into environment variable to be read by main program
// https://stackoverflow.com/questions/43753491/include-git-commit-hash-as-string-into-rust-program

fn main() {
    let git_hash = match Command::new("git").args(&["rev-parse", "HEAD"]).output() {
        Ok(output) => String::from_utf8(output.stdout).unwrap_or_default(),
        Err(_) => String::from(""),
    };
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
}