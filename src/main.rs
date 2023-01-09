use ferrisetw::native::etw_types::EventRecord;
use ferrisetw::parser::{Parser, TryParse};
use ferrisetw::provider::*;
use ferrisetw::schema::SchemaLocator;
use ferrisetw::trace::*;
use std::collections::{HashMap};
use std::error::Error;
use std::result::Result;
use std::sync::Mutex;
use std::time::Duration;

use windows::{core::*, Win32::Storage::FileSystem::*};

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref IRP_MAP: Mutex<HashMap<u64, String>> = Mutex::new(HashMap::new());
    static ref DEVICE_MAP: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

const EVENT_FILEIO_CREATE: u8 = 64;
const EVENT_FILEIO_OP_END: u8 = 76;

const NAME_NOT_FOUND: u32 = 0xc0000034;
const PATH_NOT_FOUND: u32 = 0xc000003a;

const END: &str = ".dll";

macro_rules! u {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_err) => {
                // println!("Error: {:?} getting Filename", err);
                return;
            }
        }
    };
}

macro_rules! r {
    ( $e:expr ) => {
        match $e {
            Some(x) => x,
            None => {
                return;
            }
        }
    };
}

macro_rules! ro {
    ( $e:expr ) => {
        match $e {
            Some(x) => x,
            None => {
                return Ok(());
            }
        }
    };
}

macro_rules! e {
    ( $e:expr, $s:expr ) => {
        $e.or(Err($s))
    };
}

fn update_device_path_map() -> Result<(), Box<dyn Error>> {
    let mut map = e!(DEVICE_MAP.lock(), "Failed to get device map mutex")?;
    let mut device_path: [u16; 1024] = [0; 1024];

    // Check every possible drive letter
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string().chars() {
        device_path.fill(0);
        unsafe {
            // Get DOS_PATH as a utf-16 string
            let dos_path: String = format!("{c}:");
            let mut dos_path16: Vec<u16> = dos_path.encode_utf16().collect();
            dos_path16.push(0);
            let dos_path16 = PCWSTR::from_raw(dos_path16.as_ptr());

            let r = QueryDosDeviceW(dos_path16, Some(device_path.as_mut_slice()));
            if r > 0 {
                let device_path = e!(
                    PCWSTR(device_path.as_mut_ptr()).to_string(),
                    "Failed to convert dive_path to rust string"
                )?;
                println!("map['{device_path}'] = '{dos_path}'");
                map.insert(device_path, dos_path);
            }
        }
    }
    Ok(())
}

fn check_permissions(mut path: String) -> Result<(), Box<dyn Error>> {
    let split: Vec<&str> = path.split('\\').collect();
    if split.len() < 3 {
        return Ok(());
    }

    let dos_path = "\\".to_string() + &split[1..3].join("\\");

    if let Ok(map) = DEVICE_MAP.lock() {
        if let Some(device_path) = map.get(&dos_path) {
            path.replace_range(..dos_path.len(), device_path);
        } else {
            // Maybe map needs updating
            // update_device_path_map();
        }
        println!("FileName: {}", path);
    }

    Ok(())
}

fn callback_file_io(record: EventRecord, schema_locator: &mut SchemaLocator) {
    // We locate the Schema for the Event
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            let opcode = schema.opcode();
            if opcode == EVENT_FILEIO_CREATE {
                let mut parser = Parser::create(&schema);

                let filename = u!(TryParse::<String>::try_parse(&mut parser, "OpenPath"));
                if !filename.to_lowercase().ends_with(END) {
                    return;
                }

                let irp = u!(TryParse::<u64>::try_parse(&mut parser, "IrpPtr"));
                if let Ok(mut map) = IRP_MAP.lock() {
                    map.insert(irp, filename);
                }
            } else if opcode == EVENT_FILEIO_OP_END {
                let mut parser = Parser::create(&schema);
                let status = u!(TryParse::<u32>::try_parse(&mut parser, "NtStatus"));
                if status != NAME_NOT_FOUND && status != PATH_NOT_FOUND {
                    return;
                }
                let irp = u!(TryParse::<u64>::try_parse(&mut parser, "IrpPtr"));

                if let Ok(mut map) = IRP_MAP.lock() {
                    let filename = r!(map.get(&irp));
                    check_permissions(filename.clone());
                    map.remove(&irp);
                }
            }
        }
        Err(_err) => {
            // println!("Error {:?}", err)
        }
    };
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("----------------");
    update_device_path_map()?;

    let provider_io = Provider::kernel(&kernel_providers::FILE_IO_PROVIDER)
        .add_callback(callback_file_io)
        .build()
        .unwrap();
    let provider_init_io = Provider::kernel(&kernel_providers::FILE_INIT_IO_PROVIDER)
        .add_callback(callback_file_io)
        .build()
        .unwrap();

    let mut trace = KernelTrace::new()
        .named(String::from("HijackWatcher"))
        .enable(provider_io)
        .enable(provider_init_io)
        .start()
        .unwrap();

    std::thread::sleep(Duration::new(10000, 0));
    trace.stop();

    println!("----------------");
    Ok(())
}
