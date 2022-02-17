use rand::Rng;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::prelude::*;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug)]
struct Key {
	bytes: Vec<Vec<u8>>,
}

impl Key {
	fn new() -> Key {
		let mut bytes: Vec<Vec<u8>> = vec![vec![0u8]; 4];
		for i in 0..bytes.len() {
			bytes[i] = rand::thread_rng().gen::<[u8; 2]>().to_vec();
		}
		Key { bytes }
	}

	fn print(&self) {
		for i in 0..self.bytes.len() {
			let skp1 = format!("{: >8b}", (self.bytes[i][0] & 0xff)).replace(' ', "0");
			let skp2 = format!("{: >8b}", (self.bytes[i][1] & 0xff)).replace(' ', "0");
			println!("{skp1} {skp2}");
		}
	}

	fn from_bytes(bytes: Vec<Vec<u8>>) -> Key {
		Key { bytes }
	}
}

#[derive(Debug)]
struct Message {
	bytes: Vec<Vec<u8>>,
	text: String,
}

impl Message {
	fn from_string(text: String) -> Message {
		let text_bytes: Vec<u16> = text.encode_utf16().collect();
		let mut bytes: Vec<Vec<u8>> = vec![vec![0u8; 2]; text_bytes.len()];
		let mut i = 0;
		for byte in text_bytes {
			let twou8s = byte.to_be_bytes();
			bytes[i] = twou8s.to_vec();
			i += 1;
		}
		Message { bytes, text }
	}

	fn from_bytes(bytes: Vec<Vec<u8>>) -> Message {
		let mut text_bytes_utf16: Vec<u16> = vec![0u16; 0];
		for i in 0..bytes.len() {
			let fbyte = (bytes[i][0] & 0xff).checked_shl(8).unwrap_or(0);
			let sbyte = bytes[i][1] & 0xff;
			text_bytes_utf16.push((fbyte | sbyte) as u16);
		}
		let text = String::from_utf16(&text_bytes_utf16);
		Message {
			bytes,
			text: text.unwrap_or(String::new()),
		}
	}
}

fn encrypt(message: &Message, key: &Key) -> Message {
	let mut bytes: Vec<Vec<u8>> = vec![vec![0u8; 2]; message.bytes.len()];
	for i in 0..message.bytes.len() {
		bytes[i][0] = message.bytes[i][0] ^ key.bytes[i % 4][0];
		bytes[i][1] = message.bytes[i][1] ^ key.bytes[i % 4][1];
	}
	Message::from_bytes(bytes)
}

fn decrypt(message: &Message, key: &Key) -> Message {
	encrypt(message, key)
}

struct FreqTable {
	frequencies: Vec<HashMap<char, u32>>,
}

impl FreqTable {
	fn new() -> FreqTable {
		let mut frequencies: Vec<HashMap<char, u32>> = vec![];
		for _ in 0..4 {
			frequencies.push(HashMap::new());
		}
		FreqTable { frequencies }
	}

	fn add(&mut self, table_index: usize, ch: char) {
		*self.frequencies[table_index].entry(ch).or_insert(0) += 1
	}

	fn get_most_frequent_chars(&self) -> Vec<char> {
		let mut max_chars: Vec<char> = vec![];
		for map in &self.frequencies {
			let mut max_occ_ch: char = ' ';
			let mut max_occ: u32 = 0;
			for &c in map.keys() {
				if map.get(&c).unwrap() > &mut max_occ {
					max_occ_ch = c;
					max_occ = *map.get(&c).unwrap();
				}
			}
			max_chars.push(max_occ_ch);
		}
		max_chars
	}
}

fn format_contents(contents: String) -> String {
	contents
		.nfd()
		.collect::<String>()
		.replace(|c: char| !c.is_ascii(), "")
		.replace(|c: char| !c.is_alphanumeric(), "")
		.to_uppercase()
}

fn analyze_chars_frequencies(mut freq_table: FreqTable, contents: &String) -> Vec<char> {
	let contents_chars: Vec<char> = contents.chars().collect();
	for i in 0..contents_chars.len() {
		freq_table.add(i % 4, contents_chars[i]);
	}
	freq_table.get_most_frequent_chars()
}

fn main() {
	let mut args: env::Args = env::args();
	args.next();
	let fpath = match args.next() {
		Some(f) => f,
		None => panic!("no path supplied"),
	};

	let dir_name = format!("runs/{:?}/", chrono::offset::Local::now());
	print!("Spawning dirs...");
	let _ = match fs::create_dir_all(&dir_name) {
		Ok(_) => (),
		Err(err) => panic!("could not create results directory: {err}"),
	};
	println!("\t\t\t\tOK");

	print!("Generating encryption key...");
	let key = Key::new();
	println!("\t\t\t\tOK");
	key.print();
	print!("Reading from {fpath}... ");
	let mut contents = match fs::read_to_string(&fpath) {
		Ok(con) => con,
		Err(err) => panic!("could not read {fpath}: {err}"),
	};
	println!("\t\t\t\tOK");
	contents = format_contents(contents);
	print!("Encrypting file contents...");
	let encrypted_contents = encrypt(&Message::from_string(contents), &key).text;
	let mut enc_fname = dir_name.clone();
	enc_fname.push_str("enc.txt");
	let mut encrypted_file = match File::create(&enc_fname) {
		Ok(f) => f,
		Err(err) => panic!("could not create {enc_fname}: {err}"),
	};
	let enc_bytes: Vec<u8> = encrypted_contents.bytes().collect();
	match encrypted_file.write(&enc_bytes) {
		Err(err) => panic!("could not write to file {enc_fname}: {err}"),
		Ok(_) => (),
	};
	println!("\t\t\t\t\tOK ({enc_fname})");
	print!("Analyzing chars frequencies...");
	let most_freq_chars = analyze_chars_frequencies(FreqTable::new(), &encrypted_contents);
	println!("\t\t\t\tOK");

	print!("Generating potential decryption key...");
	let e_bytes = Message::from_string(String::from("E")).bytes;
	let mut decryption_key_bytes = vec![vec![0u8; 2]; 4];
	for i in 0..most_freq_chars.len() {
		let snd_most_freq_char_bytes = Message::from_string(String::from(most_freq_chars[i])).bytes;
		decryption_key_bytes[i][0] = e_bytes[0][0] ^ snd_most_freq_char_bytes[0][0];
		decryption_key_bytes[i][1] = e_bytes[0][1] ^ snd_most_freq_char_bytes[0][1];
	}
	let new_key = Key::from_bytes(decryption_key_bytes);
	println!("\t\t\t\tOK");
	new_key.print();

	print!("Decrypting...");
	let decryption_attempt = decrypt(&Message::from_string(encrypted_contents), &new_key).text;
	let mut dec_fname = dir_name.clone();
	dec_fname.push_str("dec.txt");
	let mut decrypted_file = match File::create(&dec_fname) {
		Ok(f) => f,
		Err(err) => panic!("could not create {dec_fname}: {err}"),
	};
	let dec_bytes: Vec<u8> = decryption_attempt.bytes().collect();
	match decrypted_file.write(&dec_bytes) {
		Err(err) => panic!("could not write to file {enc_fname}: {err}"),
		Ok(_) => (),
	};
	println!("\t\t\t\tOK ({dec_fname})");
}
