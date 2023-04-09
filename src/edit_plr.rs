use std::fs::{
    read,
    write,
};
use std::io::{
    Read,
    Write,
    Cursor,
    Seek,
    SeekFrom,
};

use aes::Aes128;
use block_padding::NoPadding;
use cipher::{
    BlockDecryptMut,
    BlockEncryptMut,
    KeyIvInit,
};

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;

use byteorder::{
    LittleEndian,
    ReadBytesExt,
    WriteBytesExt,
};

use serde::{
    Serialize,
    Deserialize,
};
use serde_json;

pub fn decrypt_plr_aes128cbc(mut data: Vec<u8>, key: &[u8]) -> Vec<u8> {
    let cipher = Aes128CbcDec::new(key.into(), key.into());
    return cipher.decrypt_padded_mut::<NoPadding>(data.as_mut_slice()).expect("Error decrypting ciphertext").to_owned();
}

pub fn encrypt_plr_aes128cbc(mut data: Vec<u8>, key: &[u8]) -> Vec<u8> {
    let b = 16 - (data.len() & 15);
    data.extend(vec![u8::try_from(b).expect("Error padding"); b]);
    let cipher = Aes128CbcEnc::new(key.into(), key.into());
    return cipher.encrypt_padded_vec_mut::<NoPadding>(&data.as_slice());
}

pub fn deserialize_raw_to_struct_plr(data: Vec<u8>) -> Plr {
    let mut reader = Cursor::new(&data);

    let version: u32 = PlrUnpacker::r_u32(&mut reader);
    let company: String = PlrUnpacker::r_string(&mut reader, 7);
    let file_type: u8 = PlrUnpacker::r_u8(&mut reader);

    let unknown1 = PlrUnpacker::r_bytes(&mut reader, 12);

    let name_length: u8 = PlrUnpacker::r_u8(&mut reader);
    let name: String = PlrUnpacker::r_string(&mut reader, name_length as usize);
    let difficulty: i8 = PlrUnpacker::r_i8(&mut reader);
    let play_time: i64 = PlrUnpacker::r_i64(&mut reader);

    let hair_style: i32 = PlrUnpacker::r_i32(&mut reader);
    let hair_dye: u8 = PlrUnpacker::r_u8(&mut reader);
    let hide_visual: u16 = PlrUnpacker::r_u16(&mut reader);
    let hide_misc: u8 = PlrUnpacker::r_u8(&mut reader);
    let gender: u8 = PlrUnpacker::r_u8(&mut reader);

    let stat_life: i32 = PlrUnpacker::r_i32(&mut reader);
    let stat_life_max: i32 = PlrUnpacker::r_i32(&mut reader);
    let stat_mana: i32 = PlrUnpacker::r_i32(&mut reader);
    let stat_mana_max: i32 = PlrUnpacker::r_i32(&mut reader);
    let extra_accessory: bool = PlrUnpacker::r_bool(&mut reader);

    let done_dundefii_event: bool = PlrUnpacker::r_bool(&mut reader);

    let tax_money: i32 = PlrUnpacker::r_i32(&mut reader);

    let hair_colour: i32 = PlrUnpacker::r_i32(&mut reader);
    let skin_colour: i32 = PlrUnpacker::r_i32(&mut reader);
    let eye_colour: i32 = PlrUnpacker::r_i32(&mut reader);
    let shirt_colour: i32 = PlrUnpacker::r_i32(&mut reader);
    let undershirt_colour: i32 = PlrUnpacker::r_i32(&mut reader);
    let pants_colour: i32 = PlrUnpacker::r_i32(&mut reader);
    let shoes_colour: i32 = PlrUnpacker::r_i32(&mut reader);

    let unknown2 = PlrUnpacker::r_bytes(&mut reader, 10);

    let armor: [Equipment; 3] = [
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)}
    ];
    let accessories: [Equipment; 6] = [
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)}
    ];

    let unknown3 = PlrUnpacker::r_bytes(&mut reader, 20);

    let accessories_vanity: [Equipment; 6] = [
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)}
    ];

    let unknown4 = PlrUnpacker::r_bytes(&mut reader, 5);

    let dyes: [Equipment; 8] = [
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
        Equipment {id: PlrUnpacker::r_i32(&mut reader), prefix: PlrUnpacker::r_u8(&mut reader)},
    ];

    let unknown5 = PlrUnpacker::r_bytes(&mut reader, 10);

    let mut inventory1: [Item; 32] = [Item::default(); 32];
    let mut inventory2: [Item; 26] = [Item::default(); 26];
    for idx in 0..32 {
        let id: i32 = PlrUnpacker::r_i32(&mut reader);
        if id == 0 || id > 5455 {
            reader.seek(SeekFrom::Current(6)).expect("Error seeking forward in the data");
        } else {
            inventory1[idx] = Item {
                id: id,
                stack: PlrUnpacker::r_i32(&mut reader),
                prefix: PlrUnpacker::r_u8(&mut reader),
                favourites: PlrUnpacker::r_bool(&mut reader)
            };
        }
    }
    for idx in 0..26 {
        let id: i32 = PlrUnpacker::r_i32(&mut reader);
        if id == 0 || id > 5455 {
            reader.seek(SeekFrom::Current(6)).expect("Error seeking forward in the data");
        } else {
            inventory2[idx] = Item {
                id: id,
                stack: PlrUnpacker::r_i32(&mut reader),
                prefix: PlrUnpacker::r_u8(&mut reader),
                favourites: PlrUnpacker::r_bool(&mut reader)
            };
        }
    }

    let plr = Plr {
        version: version,
        company: company,
        file_type: file_type,
        UNKNOWN1: unknown1,
        name_length: name_length,
        name: name,
        difficulty: difficulty,
        play_time: play_time,
        appearance: Appearance {
            hair_style: hair_style,
            hair_dye: hair_dye,
            hide_visual: hide_visual,
            hide_misc: hide_misc,
            gender: gender,
            hair_colour: hair_colour,
            skin_colour: skin_colour,
            eye_colour: eye_colour,
            shirt_colour: shirt_colour,
            undershirt_colour: undershirt_colour,
            pants_colour: pants_colour,
            shoes_colour: shoes_colour },
        stat_life: stat_life,
        stat_life_max: stat_life_max,
        stat_mana: stat_mana,
        stat_mana_max: stat_mana_max,
        extra_accessory: extra_accessory,
        done_dundefii_event: done_dundefii_event,
        tax_money: tax_money,
        // appearance: Appearance{}, // The rest of the appearance
        UNKNOWN2: unknown2,
        armor: armor,
        accessories: accessories,
        UNKNOWN3: unknown3,
        accessories_vanity: accessories_vanity,
        UNKNOWN4: unknown4,
        dyes: dyes,
        UNKNOWN5: unknown5,
        inventory1: inventory1,
        inventory2: inventory2,
        UNKNOWN6: data[reader.position() as usize..].to_vec(),
        raw_length_bytes: data.len()
    };

    return plr;
}

pub fn serialize_struct_to_raw_plr(plr: &Plr) -> Vec<u8> {
    let mut data: Vec<u8> = vec![0; plr.raw_length_bytes];

    {
        let mut writer = Cursor::new(&mut data);

        PlrPacker::w_u32(&mut writer, plr.version);
        PlrPacker::w_string(&mut writer, &plr.company);
        PlrPacker::w_u8(&mut writer, plr.file_type);

        PlrPacker::w_bytes(&mut writer, plr.UNKNOWN1.to_owned());

        PlrPacker::w_u8(&mut writer, plr.name_length);
        PlrPacker::w_string(&mut writer, &plr.name);
        PlrPacker::w_i8(&mut writer, plr.difficulty);
        PlrPacker::w_i64(&mut writer, plr.play_time);

        PlrPacker::w_i32(&mut writer, plr.appearance.hair_style);
        PlrPacker::w_u8(&mut writer, plr.appearance.hair_dye);
        PlrPacker::w_u16(&mut writer, plr.appearance.hide_visual);
        PlrPacker::w_u8(&mut writer, plr.appearance.hide_misc);
        PlrPacker::w_u8(&mut writer, plr.appearance.gender);

        PlrPacker::w_i32(&mut writer, plr.stat_life);
        PlrPacker::w_i32(&mut writer, plr.stat_life_max);
        PlrPacker::w_i32(&mut writer, plr.stat_mana);
        PlrPacker::w_i32(&mut writer, plr.stat_mana_max);
        PlrPacker::w_bool(&mut writer, plr.extra_accessory);

        PlrPacker::w_bool(&mut writer, plr.done_dundefii_event);

        PlrPacker::w_i32(&mut writer, plr.tax_money);

        PlrPacker::w_i32(&mut writer, plr.appearance.hair_colour);
        PlrPacker::w_i32(&mut writer, plr.appearance.skin_colour);
        PlrPacker::w_i32(&mut writer, plr.appearance.eye_colour);
        PlrPacker::w_i32(&mut writer, plr.appearance.shirt_colour);
        PlrPacker::w_i32(&mut writer, plr.appearance.undershirt_colour);
        PlrPacker::w_i32(&mut writer, plr.appearance.pants_colour);
        PlrPacker::w_i32(&mut writer, plr.appearance.shoes_colour);
        
        PlrPacker::w_bytes(&mut writer, plr.UNKNOWN2.to_owned());

        plr.armor.map(|e| {PlrPacker::w_i32(&mut writer, e.id); PlrPacker::w_u8(&mut writer, e.prefix)});
        plr.accessories.map(|e| {PlrPacker::w_i32(&mut writer, e.id); PlrPacker::w_u8(&mut writer, e.prefix)});
        
        PlrPacker::w_bytes(&mut writer, plr.UNKNOWN3.to_owned());
        
        plr.accessories_vanity.map(|e| {PlrPacker::w_i32(&mut writer, e.id); PlrPacker::w_u8(&mut writer, e.prefix)});

        PlrPacker::w_bytes(&mut writer, plr.UNKNOWN4.to_owned());

        plr.dyes.map(|e| {PlrPacker::w_i32(&mut writer, e.id); PlrPacker::w_u8(&mut writer, e.prefix)});

        PlrPacker::w_bytes(&mut writer, plr.UNKNOWN5.to_owned());

        plr
            .inventory1
            .map(
                |i| {
                    PlrPacker::w_i32(&mut writer, i.id);
                    PlrPacker::w_i32(&mut writer, i.stack);
                    PlrPacker::w_u8(&mut writer, i.prefix);
                    PlrPacker::w_bool(&mut writer, i.favourites);
                }
            )
        ;
        plr
            .inventory2
            .map(
                |i| {
                    PlrPacker::w_i32(&mut writer, i.id);
                    PlrPacker::w_i32(&mut writer, i.stack);
                    PlrPacker::w_u8(&mut writer, i.prefix);
                    PlrPacker::w_bool(&mut writer, i.favourites);
                }
            )
        ;

        PlrPacker::w_bytes(&mut writer, plr.UNKNOWN6.to_owned());
    }

    return data;
}

pub fn deconstruct_plr(plr_file: Vec<u8>, key: &[u8]) -> Plr {
    let raw = decrypt_plr_aes128cbc(plr_file, key);
    let plr = deserialize_raw_to_struct_plr(raw);
    let data = serde_json::to_string(&plr).expect("Error serializing PLR to JSON");
    write(format!("./DECRYPTED_{}.json", plr.name), data).expect("Error writing decrypted data to file");
    return plr;
}

pub fn reconstruct_plr(data: Vec<u8>, key: &[u8]) -> Plr {
    let plr = serde_json::from_slice(data.as_slice()).expect("Error deserializing JSON into plr");
    let raw = serialize_struct_to_raw_plr(&plr);
    let encrypted = encrypt_plr_aes128cbc(raw, key);
    write(format!("./COPY_{}.plr", &plr.name), encrypted).expect("Error serializing PLR");
    return plr;
}

struct PlrUnpacker;

impl PlrUnpacker {
    pub fn r_i8<R: Read + Seek>(reader: &mut R) -> i8 {
        return reader.read_i8().expect("Error reading byte as int8");
    }

    pub fn r_u8<R: Read + Seek>(reader: &mut R) -> u8 {
        return reader.read_u8().expect("Error reading byte as uint8");
    }

    pub fn r_u16<R: Read + Seek>(reader: &mut R) -> u16 {
        return reader.read_u16::<LittleEndian>().expect("Error reading bytes as uint16");
    }

    pub fn r_i32<R: Read + Seek>(reader: &mut R) -> i32 {
        return reader.read_i32::<LittleEndian>().expect("Error reading bytes as int32");
    }

    pub fn r_u32<R: Read + Seek + std::fmt::Debug>(reader: &mut R) -> u32 {
        return reader.read_u32::<LittleEndian>().expect("Error reading bytes as uint32");
    }

    pub fn r_i64<R: Read + Seek>(reader: &mut R) -> i64 {
        return reader.read_i64::<LittleEndian>().expect("Error reading bytes as int64");
    }

    pub fn r_bool<R: Read + Seek>(reader: &mut R) -> bool {
        return reader.read_u8().expect("Error reading byte as bool") != 0;
    }

    pub fn r_bytes<R: Read + Seek>(reader: &mut R, n: usize) -> Vec<u8> {
        let mut _buf = vec![0; n];
        let buf = _buf.as_mut_slice();
        let _n = reader.read_exact(buf).expect("Error reading bytes");
        return buf.to_vec();
    }

    pub fn r_string<R: Read + Seek>(reader: &mut R, l: usize) -> String {
        let mut buf = vec![0; l];
        let _n = reader.read_exact(&mut buf).expect("Error reading bytes");
        return String::from_utf8(buf).expect("Error converting byte vector into String");
    }
}

struct PlrPacker;

impl PlrPacker {
    pub fn w_i8<W: Write + Seek>(writer: &mut W, v: i8) -> usize {
        writer.write_i8(v).expect("Error writing signed byte to buffer");
        return 1;
    }

    pub fn w_u8<W: Write + Seek>(writer: &mut W, v: u8) -> usize {
        writer.write_u8(v).expect("Error writing unsigned byte to buffer");
        return 1;
    }

    pub fn w_u16<W: Write + Seek>(writer: &mut W, v: u16) -> usize {
        writer.write_u16::<LittleEndian>(v).expect("Error writing int32 to buffer");
        return 2;
    }

    pub fn w_i32<W: Write + Seek>(writer: &mut W, v: i32) -> usize {
        writer.write_i32::<LittleEndian>(v).expect("Error writing int32 to buffer");
        return 4;
    }

    pub fn w_u32<W: Write + Seek>(writer: &mut W, v: u32) -> usize {
        writer.write_u32::<LittleEndian>(v).expect("Error writing uint32 to buffer");
        return 4;
    }

    pub fn w_i64<W: Write + Seek>(writer: &mut W, v: i64) -> usize {
        writer.write_i64::<LittleEndian>(v).expect("Error writing int64 to buffer");
        return 8;
    }

    pub fn w_bool<W: Write + Seek>(writer: &mut W, v: bool) -> usize {
        writer.write_u8(if v {1} else {0}).expect("Error writing bool as uint8 to buffer");
        return 1;
    }

    pub fn w_bytes<W: Write + Seek>(writer: &mut W, v: Vec<u8>) -> usize {
        return writer.write(&v).expect("Error writing bytes to buffer");
    }

    pub fn w_string<W: Write + Seek>(writer: &mut W, v: &str) -> usize {
        writer.write(v.as_bytes()).expect("Error writing String to buffer");
        return 0;
    }
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Default,
    Clone,
    Copy,
)]
pub struct Appearance {
    pub hair_style: i32,
    pub hair_dye: u8,
    pub hide_visual: u16,
    pub hide_misc: u8,
    pub gender: u8,

    pub hair_colour: i32,
    pub skin_colour: i32,
    pub eye_colour: i32,
    pub shirt_colour: i32,
    pub undershirt_colour: i32,
    pub pants_colour: i32,
    pub shoes_colour: i32,
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Default,
    Clone,
    Copy,
)]
pub struct Equipment {
    pub id: i32,
    pub prefix: u8
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Default,
    Clone,
    Copy,
)]
pub struct Item {
    pub id: i32,
    pub stack: i32,
    pub prefix: u8,
    pub favourites: bool
}

#[allow(non_snake_case)]
#[derive(
    Serialize,
    Deserialize,
    Debug,
    Default,
)]
pub struct Plr {
    pub version: u32,
    pub company: String,
    pub file_type: u8,
    pub UNKNOWN1: Vec<u8>, // 12 bytes
    pub name_length: u8,
    pub name: String,
    pub difficulty: i8,
    pub play_time: i64,
    pub appearance: Appearance,
    pub stat_life: i32,
    pub stat_life_max: i32,
    pub stat_mana: i32,
    pub stat_mana_max: i32,
    pub extra_accessory: bool,
    pub done_dundefii_event: bool,
    pub tax_money: i32,
    // pub appearance: Appearance, // The rest of the appearance
    pub UNKNOWN2: Vec<u8>, // 10 bytes
    pub armor: [Equipment; 3],
    // armor: [(Equipment, Equipment, Equipment)],
    pub accessories: [Equipment; 6],
    // accessories: [(Equipment, Equipment, Equipment, Equipment, Equipment, Equipment)],
    pub UNKNOWN3: Vec<u8>, // 20 bytes
    pub accessories_vanity: [Equipment; 6],
    // accessories_vanity: [(Equipment, Equipment, Equipment, Equipment, Equipment, Equipment)],
    pub UNKNOWN4: Vec<u8>, // 5 bytes
    pub dyes: [Equipment; 8],
    // dyes: [(Equipment, Equipment, Equipment, Equipment, Equipment, Equipment, Equipment, Equipment)],
    pub UNKNOWN5: Vec<u8>, // 10 bytes
    pub inventory1: [Item; 32],
    pub inventory2: [Item; 26],
    pub UNKNOWN6: Vec<u8>, // Stuff like misc_equipments(id, prefix) misc_dyes(id, prefix) piggy_bank(id, stack, prefix) safe(id, stack, prefix) buffs(id, duration) world_list(if_-1_skip, spawn_x, spawn_y, address, name) hotbar_locked(bool) hide_statuses_under_map(bool[]) fishing_quests_completed(int32) dpa_bindings(int32) builder_account_status(int32) bartender_quests(int32) mod_data padding
    pub raw_length_bytes: usize
}

impl Plr {
    #[allow(unused)]
    fn print_plr(plr: &Plr) {
        println!(
            "
            version:\t\t{}
            company:\t\t{}
            file_type:\t\t{}
            UNKNOWN DATA
            name_length:\t{}
            name:\t\t{}
            difficulty:\t\t{}
            play_time:\t\t{}
            appearance:\t\t{:?}
            stat_life:\t\t{}
            stat_life_max:\t{}
            stat_mana:\t\t{}
            stat_mana_max:\t{}
            extra_accessory:\t{}
            done_dundefii_event:\t{}
            tax_money:\t\t{}
            OTHER HALF OF APPEARANCE
            UNKNOWN DATA
            ",
            plr.version,
            plr.company,
            plr.file_type,
            plr.name_length,
            plr.name,
            plr.difficulty,
            plr.play_time,
            plr.appearance,
            plr.stat_life,
            plr.stat_life_max,
            plr.stat_mana,
            plr.stat_mana_max,
            plr.extra_accessory,
            plr.done_dundefii_event,
            plr.tax_money,
        );
        plr.armor.map(|e| println!("armor:\t{:?}", e));
        plr.accessories.map(|e| println!("accessories:\t{:?}", e));
        plr.accessories_vanity.map(|e| println!("accessories_vanity:\t{:?}", e));
        plr.dyes.map(|e| println!("dyes:\t{:?}", e));
        plr.inventory1.map(|i| println!("{:?}", i));
        plr.inventory2.map(|i| println!("{:?}", i));
        println!("UNKNOWN DATA\nNumber of bytes:{}", plr.raw_length_bytes);
    }
}
