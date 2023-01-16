use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::c_void;
use std::fs::{remove_file, OpenOptions};
use std::io::ErrorKind::{NotFound, PermissionDenied};
use std::mem::size_of_val;
use std::path::Path;
use std::result::Result;
use std::sync::mpsc::Sender;
use std::sync::{mpsc, Arc, Mutex, MutexGuard};


use ferrisetw::parser::Parser;
use ferrisetw::provider::*;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::*;
use ferrisetw::EventRecord;

use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Security::AppLocker::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::SystemServices::*;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref IRP_MAP_PID: Mutex<HashMap<u32, HashMap<u64, String>>> = Mutex::new(HashMap::new());
    static ref IRP_MAP: Mutex<HashMap<u64, String>> = Mutex::new(HashMap::new());
    static ref DEVICE_MAP: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    static ref FILES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
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
                // println!("Error: {err:?} ");
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

fn update_device_path_map(
    map: &mut MutexGuard<HashMap<String, String>>,
) -> Result<(), Box<dyn Error>> {
    let mut device_path: [u16; 1024] = [0; 1024];

    // Check every possible drive letter
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string().chars() {
        device_path.fill(0);
        unsafe {
            // Get DOS_PATH as a utf-16 string
            let dos_path = format!("{c}:");
            let mut dos_path_pcw: Vec<u16> = dos_path.encode_utf16().collect();
            dos_path_pcw.push(0);
            let dos_path_pcw = PCWSTR::from_raw(dos_path_pcw.as_ptr());

            // Use API to lookup path
            let r = QueryDosDeviceW(dos_path_pcw, Some(device_path.as_mut_slice()));
            if r > 0 {
                let device_path = PCWSTR(device_path.as_mut_ptr())
                    .to_string()
                    .or(Err("Failed to convert dive_path to rust string"))?;
                println!("map['{device_path}'] = '{dos_path}'");
                map.insert(device_path, dos_path);
            }
        }
    }
    Ok(())
}

fn check_permissions(filename: &String) -> Result<(), Box<dyn Error>> {
    let path = Path::new(&filename);
    let aready_existed = path.exists();
    if aready_existed {
        return Ok(());
    }

    let mut opened = false;
    match OpenOptions::new()
        .create(true)
        .append(true) // So we don't overwrite existing data
        .open(path)
    {
        Ok(_) => {
            println!("[+] Opened - {filename}");
            opened = true;
        }
        Err(error) => match error.kind() {
            PermissionDenied => {
                println!("[ ] PermissionDenied - {filename}");
            }
            NotFound => {
                println!("[ ] NotFound - {filename}");
            }
            err => {
                println!("[ ] Other Error - {err} - {filename}");
            }
        },
    }
    if opened && !aready_existed {
        remove_file(path)?;
    }
    Ok(())
}

fn check_path(mut path: String, tx: &Arc<Mutex<Sender<String>>>) -> Result<(), Box<dyn Error>> {
    let split: Vec<&str> = path.split('\\').collect();
    if split.len() < 3 {
        return Ok(());
    }

    let dos_path = "\\".to_string() + &split[1..3].join("\\");

    let mut map = DEVICE_MAP.lock().or(Err("Failed to get Device map"))?;

    if let Some(device_path) = map.get(&dos_path) {
        path.replace_range(..dos_path.len(), device_path);
    } else {
        // Maybe map needs updating, e.g. new device plugged in
        update_device_path_map(&mut map)?;
        if let Some(device_path) = map.get(&dos_path) {
            path.replace_range(..dos_path.len(), device_path);
        }
    }

    let mut files = FILES.lock().or(Err("Failed to get Device map"))?;
    if !files.contains(&path) {
        let txpath = path.clone();
        if let Ok(tx) = tx.lock() {
            tx.send(txpath).unwrap();
        }
        files.insert(path);
    }

    Ok(())
}

fn callback_file_io(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    tx: &Arc<Mutex<Sender<String>>>,
) {
    // We locate the Schema for the Event
    let schema = u!(schema_locator.event_schema(record));

    let opcode = record.opcode();
    let _pid = record.process_id();
    if opcode == EVENT_FILEIO_CREATE {
        let parser = Parser::create(record, &schema);
        let filename = u!(parser.try_parse::<String>("OpenPath"));
        if !filename.to_lowercase().ends_with(END) {
            return;
        }

        let irp = u!(parser.try_parse::<u64>("IrpPtr"));
        if let Ok(mut map) = IRP_MAP.lock() {
            map.insert(irp, filename);
        }
    } else if opcode == EVENT_FILEIO_OP_END {
        let parser = Parser::create(record, &schema);
        let status = u!(parser.try_parse::<u32>("NtStatus"));

        if status != NAME_NOT_FOUND && status != PATH_NOT_FOUND {
            return;
        }
        let irp = u!(parser.try_parse::<u64>("IrpPtr"));

        if let Ok(mut map) = IRP_MAP.lock() {
            let filename = r!(map.get(&irp));
            _ = check_path(filename.clone(), tx);
            map.remove(&irp);
        }
    }
}

// Lower Privliges to regular user
fn lower_privs() {
    unsafe {
        let mut result: BOOL;
        let mut token: HANDLE = INVALID_HANDLE_VALUE;
        let mut hlevel: SAFER_LEVEL_HANDLE = SAFER_LEVEL_HANDLE(0);

        result = SaferCreateLevel(
            SAFER_SCOPEID_USER,
            SAFER_LEVELID_NORMALUSER,
            SAFER_LEVEL_OPEN,
            &mut hlevel,
            None,
        );
        if result.0 == 0 {
            println!("[e] SaferCreateLevel: {}", GetLastError().to_hresult());
            return;
        }

        result = SaferComputeTokenFromLevel(
            hlevel,
            None,
            &mut token,
            SAFER_COMPUTE_TOKEN_FROM_LEVEL_FLAGS(0),
            None,
        );
        if result.0 == 0 {
            println!(
                "[e] SaferComputeTokenFromLevel: {}",
                GetLastError().to_hresult()
            );
            return;
        }
        SaferCloseLevel(hlevel);

        let mut psid = PSID::default();
        result = ConvertStringSidToSidA(s!("S-1-16-8192"), &mut psid);
        if result.0 == 0 {
            println!(
                "[e] ConvertStringSidToSidA: {}",
                GetLastError().to_hresult()
            );
            return;
        }
        let mut tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Attributes: SE_GROUP_INTEGRITY.try_into().unwrap(),
                Sid: psid,
            },
        };
        // the fuck is this line look like this
        let tml_ptr: *mut c_void = &mut tml as *mut _ as *mut c_void;

        // Can't combine these lines without compiler warning...
        let mut tml_size: u32 = size_of_val(&tml).try_into().unwrap();
        tml_size += GetLengthSid(tml.Label.Sid);

        result = SetTokenInformation(token, TokenIntegrityLevel, tml_ptr, tml_size);
        if result.0 == 0 {
            println!("[e] SetTokenInformation: {}", GetLastError().to_hresult());
            return;
        }

        result = ImpersonateLoggedOnUser(token);
        if result.0 == 0 {
            println!(
                "[e] ImpersonateLoggedOnUser: {}",
                GetLastError().to_hresult()
            );
            return;
        }

        println!("Good?");
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("----------------");
    // Create channel for ITC
    let (tx1, rx) = mpsc::channel();
    let tx2 = tx1.clone();
    let tx1 = Arc::new(Mutex::new(tx1));
    let tx2 = Arc::new(Mutex::new(tx2));

    // Start thread to handle permissions check
    std::thread::spawn(move || {
        lower_privs();
        loop {
            let path: String = rx.recv().unwrap();
            _ = check_permissions(&path);
        }
    });

    // Update device map
    if let Ok(mut map) = DEVICE_MAP.lock() {
        update_device_path_map(&mut map)?;
    }

    // Prepare ETW Providers
    let provider_io = Provider::kernel(&kernel_providers::FILE_IO_PROVIDER)
        .add_callback(
            move |record: &EventRecord, schema_locator: &SchemaLocator| {
                callback_file_io(record, schema_locator, &tx1);
            },
        )
        .build();
    let provider_init_io = Provider::kernel(&kernel_providers::FILE_INIT_IO_PROVIDER)
        .add_callback(
            move |record: &EventRecord, schema_locator: &SchemaLocator| {
                callback_file_io(record, schema_locator, &tx2);
            },
        )
        .build();

    // Prepare ETW Session
    let (mut trace, _) = KernelTrace::new()
        .named(String::from("HijackWatcher"))
        .enable(provider_io)
        .enable(provider_init_io)
        .start()
        .unwrap();

    // Trace on current thread
    trace.process().unwrap();
    trace.stop().unwrap();
    println!("----------------");
    Ok(())
}
