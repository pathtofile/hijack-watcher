use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::c_void;
use std::fs::{remove_file, OpenOptions};
use std::io::ErrorKind::{NotFound, PermissionDenied};
use std::mem::size_of_val;
use std::path::Path;
use std::process::Command;
use std::result::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{mpsc, Arc, Mutex, MutexGuard};

use clap::Parser as ClapParser;
use serde_json::json;

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

// FileIO ETW Event IDs
const EVENT_FILEIO_CREATE: u8 = 64;
const EVENT_FILEIO_OP_END: u8 = 76;

// Process ETW Event IDs
const EVENT_TRACE_TYPE_START: u8 = 1;
const EVENT_TRACE_TYPE_END: u8 = 2;
const EVENT_TRACE_TYPE_DCSTART: u8 = 3;

const NAME_NOT_FOUND: u32 = 0xc0000034;
const PATH_NOT_FOUND: u32 = 0xc000003a;

const END: &str = ".dll";

struct ETWEvent {
    pid: u32,
    commandline: String,
    imagename: String,
}
struct FEvent {
    etw_event: ETWEvent,
    filename: String,
}

lazy_static! {
    static ref IRP_MAP: Mutex<HashMap<u64, String>> = Mutex::new(HashMap::new());
    static ref DEVICE_MAP: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    static ref FILES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    static ref PID_MAP: Mutex<HashMap<u32, ETWEvent>> = Mutex::new(HashMap::new());
}

static VERBOSE: AtomicBool = AtomicBool::new(false);

// This is a "simple" macro to do verbose printing
macro_rules! vprintln {
    ($fmt_str:literal) => {{
        if VERBOSE.load(Ordering::Relaxed) {
            eprintln!($fmt_str);
        }
    }};

    ($fmt_str:literal, $($args:expr),*) => {{
        if VERBOSE.load(Ordering::Relaxed) {
            eprintln!($fmt_str, $($args),*);
        }
    }};
}

// Setup Commandline args
#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// ETW Session Name
    #[arg(short, long, default_value = "HijackWatcher")]
    name: String,

    /// Print verbose logging
    #[arg(short, long)]
    verbose: bool,
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
                vprintln!("map['{device_path}'] = '{dos_path}'");
                map.insert(device_path, dos_path);
            }
        }
    }
    Ok(())
}

fn check_permissions(event: &FEvent) -> Result<(), Box<dyn Error>> {
    let filename = &event.filename;
    let imagename = &event.etw_event.imagename;
    let pid = &event.etw_event.pid;
    let cmdline = &event.etw_event.commandline;
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
            // vprintln!("[+] {pid} - {imagename} ({cmdline}) - Opened - {filename}");
            let j = json!({
                "pid": pid,
                "imagename": imagename,
                "cmdline": cmdline,
                "filename": filename
            });
            println!("{j}");
            opened = true;
        }
        Err(error) => match error.kind() {
            PermissionDenied => {
                vprintln!("[ ] {imagename} - PermissionDenied - {filename}");
            }
            NotFound => {
                vprintln!("[ ] {imagename} - NotFound - {filename}");
            }
            err => {
                vprintln!("[ ] {imagename} - Other Error - {err} - {filename}");
            }
        },
    }
    if opened && !aready_existed {
        remove_file(path)?;
    }
    Ok(())
}

fn check_path(
    event: &ETWEvent,
    mut filename: String,
    tx: &Arc<Mutex<Sender<FEvent>>>,
) -> Result<(), Box<dyn Error>> {
    let split: Vec<&str> = filename.split('\\').collect();
    if split.len() < 3 {
        return Ok(());
    }

    let dos_path = "\\".to_string() + &split[1..3].join("\\");
    let mut map = DEVICE_MAP.lock().or(Err("Failed to get Device map"))?;
    if let Some(device_path) = map.get(&dos_path) {
        filename.replace_range(..dos_path.len(), device_path);
    } else {
        // Maybe map needs updating, e.g. new device plugged in
        update_device_path_map(&mut map)?;
        if let Some(device_path) = map.get(&dos_path) {
            filename.replace_range(..dos_path.len(), device_path);
        }
    }

    let mut files = FILES.lock().or(Err("Failed to get Device map"))?;
    if !files.contains(&filename) {
        if let Ok(tx) = tx.lock() {
            let fevent = FEvent {
                etw_event: ETWEvent {
                    pid: event.pid,
                    commandline: event.commandline.clone(),
                    imagename: event.imagename.clone(),
                },
                filename: filename.clone(),
            };
            tx.send(fevent).unwrap();
        }
        files.insert(filename);
    }

    Ok(())
}

fn callback_file_io(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    tx: &Arc<Mutex<Sender<FEvent>>>,
) -> Result<(), Box<dyn Error>> {
    match record.opcode() {
        EVENT_FILEIO_CREATE => {
            // We locate the Schema for the Event
            let schema = schema_locator
                .event_schema(record)
                .or(Err("Failed to get Event Schema"))?;

            let parser = Parser::create(record, &schema);
            let filename = parser
                .try_parse::<String>("OpenPath")
                .or(Err("Failed to parse OpenPath"))?;
            if !filename.to_lowercase().ends_with(END) {
                return Ok(());
            }

            let irp = parser
                .try_parse::<u64>("IrpPtr")
                .or(Err("Failed to parse IrpPtr"))?;
            if let Ok(mut map) = IRP_MAP.lock() {
                map.insert(irp, filename);
            }
        }
        EVENT_FILEIO_OP_END => {
            // We locate the Schema for the Event
            let schema = schema_locator
                .event_schema(record)
                .or(Err("Failed to get Event Schema"))?;

            let pid = record.process_id();
            let parser = Parser::create(record, &schema);
            let status = parser
                .try_parse::<u32>("NtStatus")
                .or(Err("Failed to parse NtStatus"))?;

            if status != NAME_NOT_FOUND && status != PATH_NOT_FOUND {
                return Ok(());
            }
            let irp = parser
                .try_parse::<u64>("IrpPtr")
                .or(Err("Failed to parse IrpPtr"))?;

            let mut map_pid = PID_MAP.lock().or(Err("Failed to get Device map"))?;
            let event = map_pid.get_mut(&pid).ok_or("Failed to fin pid in map")?;

            let mut map_irp = IRP_MAP.lock().or(Err("Failed to get IRP map"))?;
            let filename = map_irp.get(&irp).ok_or("Failed to fin IRP in map")?;

            let err = check_path(event, filename.clone(), tx);
            map_irp.remove(&irp);
            err?;
        }
        _ => {}
    };

    Ok(())
}

fn callback_process(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
) -> Result<(), Box<dyn Error>> {
    match record.opcode() {
        EVENT_TRACE_TYPE_START | EVENT_TRACE_TYPE_DCSTART => {
            // We locate the Schema for the Event
            let schema = schema_locator
                .event_schema(record)
                .or(Err("Failed to get Event Schema"))?;

            let parser = Parser::create(record, &schema);
            let imagename = parser
                .try_parse::<String>("ImageFileName")
                .or(Err("Failed to parse ImageFileName"))?;
            let commandline = parser
                .try_parse::<String>("CommandLine")
                .or(Err("Failed to parse commandline"))?;
            let pid = parser
                .try_parse::<u32>("ProcessId")
                .or(Err("Failed to parse ProcessId"))?;
            let event = ETWEvent {
                pid,
                commandline,
                imagename,
            };
            if let Ok(mut map) = PID_MAP.lock() {
                map.insert(pid, event);
            }
        }
        EVENT_TRACE_TYPE_END => {
            // We locate the Schema for the Event
            let schema = schema_locator
                .event_schema(record)
                .or(Err("Failed to get Event Schema"))?;

            // Possible race condition if we get this event before
            // the final Image load events. Decided to ignore, as
            // most image laods happen long before the process ends, usually
            // much closer to the start of the process.
            if let Ok(mut map) = PID_MAP.lock() {
                let parser = Parser::create(record, &schema);
                let pid = parser
                    .try_parse::<u32>("ProcessId")
                    .or(Err("Failed to parse ProcessId"))?;
                map.remove(&pid);
            }
        }
        // Ignore other OPcodes
        _ => {}
    };

    Ok(())
}

// Lower Privliges to regular user
fn lower_privs() {
    unsafe {
        let mut res: bool;
        let mut token: HANDLE = INVALID_HANDLE_VALUE;
        let mut hlevel: SAFER_LEVEL_HANDLE = SAFER_LEVEL_HANDLE(0);

        res = SaferCreateLevel(
            SAFER_SCOPEID_USER,
            SAFER_LEVELID_NORMALUSER,
            SAFER_LEVEL_OPEN,
            &mut hlevel,
            None,
        )
        .as_bool();
        if !res {
            vprintln!("[e] SaferCreateLevel: {}", GetLastError().to_hresult());
            return;
        }

        res = SaferComputeTokenFromLevel(
            hlevel,
            None,
            &mut token,
            SAFER_COMPUTE_TOKEN_FROM_LEVEL_FLAGS(0),
            None,
        )
        .as_bool();
        if !res {
            vprintln!(
                "[e] SaferComputeTokenFromLevel: {}",
                GetLastError().to_hresult()
            );
            return;
        }
        SaferCloseLevel(hlevel);

        let mut psid = PSID::default();
        res = ConvertStringSidToSidA(s!("S-1-16-8192"), &mut psid).as_bool();
        if !res {
            vprintln!(
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

        res = SetTokenInformation(token, TokenIntegrityLevel, tml_ptr, tml_size).as_bool();
        if !res {
            vprintln!("[e] SetTokenInformation: {}", GetLastError().to_hresult());
            return;
        }

        res = ImpersonateLoggedOnUser(token).as_bool();
        if !res {
            vprintln!(
                "[e] ImpersonateLoggedOnUser: {}",
                GetLastError().to_hresult()
            );
            return;
        }

        if VERBOSE.load(Ordering::Relaxed) {
            vprintln!("[ ] Lowered thread privs?");
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    VERBOSE.store(args.verbose, Ordering::Relaxed);

    // Stop any existing trace
    Command::new("logman")
        .args(["stop", &args.name, "-ets"])
        .output()?;

    // Create channel for ITC
    let (tx1, rx) = mpsc::channel();
    let tx2 = tx1.clone();
    let tx1 = Arc::new(Mutex::new(tx1));
    let tx2 = Arc::new(Mutex::new(tx2));

    // Setup device map
    if let Ok(mut map) = DEVICE_MAP.lock() {
        update_device_path_map(&mut map)?;
    }

    // Prepare ETW Providers
    let provider_io = Provider::kernel(&kernel_providers::FILE_IO_PROVIDER)
        .add_callback(
            move |record: &EventRecord, schema_locator: &SchemaLocator| {
                _ = callback_file_io(record, schema_locator, &tx1);
            },
        )
        .build();
    let provider_init_io = Provider::kernel(&kernel_providers::FILE_INIT_IO_PROVIDER)
        .add_callback(
            move |record: &EventRecord, schema_locator: &SchemaLocator| {
                _ = callback_file_io(record, schema_locator, &tx2);
            },
        )
        .build();

    let provider_process = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(|record: &EventRecord, schema_locator: &SchemaLocator| {
            _ = callback_process(record, schema_locator);
        })
        .build();

    // Prepare ETW Session
    let (mut trace, _) = KernelTrace::new()
        .named(args.name)
        .enable(provider_process)
        .enable(provider_init_io)
        .enable(provider_io)
        .start()
        .unwrap();

    // Start thread to handle permissions check
    std::thread::spawn(move || {
        lower_privs();
        loop {
            let event: FEvent = rx.recv().unwrap();
            _ = check_permissions(&event);
        }
    });

    // Trace on current thread
    trace.process().unwrap();
    trace.stop().unwrap();
    vprintln!("----------------");
    Ok(())
}
