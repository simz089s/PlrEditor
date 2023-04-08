use std::env;

use dotenvy::dotenv;

mod edit_plr;

fn main() {
    let args: Vec<String> = env::args().collect();
    dotenv().expect("Error: .env file not found");

    let key = env::var("key").expect("Error key not found in env").encode_utf16().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
    println!("{:x?}", &key);
    let key = key.as_slice();
    let mut plr = edit_plr::deconstruct_plr(&args[1], key);
    edit_plr::reconstruct_plr(&mut plr, key);
}
