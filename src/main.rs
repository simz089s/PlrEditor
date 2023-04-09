use std::env;
use std::ffi::OsStr;
use std::fs::read;
use std::path::Path;

use dotenvy::dotenv;

mod edit_plr;

fn main() {
    let args: Vec<String> = env::args().collect();
    dotenv().expect("Error: .env file not found");

    let filepath = Path::new(&args[1]);
    let key = env::var("key").expect("Error key not found in env").encode_utf16().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
    let key = key.as_slice();

    match filepath.extension().and_then(OsStr::to_str) {
        Some("plr") => edit_plr::deconstruct_plr(read(filepath).expect("Error reading plr file"), key),
        Some("json") => edit_plr::reconstruct_plr(read(filepath).expect("Error reading JSON file"), key),

        _ => edit_plr::Plr::default(),
    };
}
