# DLL Hijack Watcher
ETW-based monitor to find potential DLL hijack oppertunities

## Overview
This Project uses [Event Tracing for Windows](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-)
to subscribe to FileIO events. Using the `CREATE` and `OP_END` events it will look for events that show
a process attempted to load a non-existant DLL.

The path to the missing DLL is then passed to a seprate low-privledged thread, which will attempt to 'create' the DLL.
If this succeeds, then it *might* be possible for a low-privledged user to hijack that program, by creating an actual
dummy DLL in that location.

This technique isn't 100%, but may serve as a useful starting point for further manual investigation.


## Build
```powershell
git clone git@github.com:pathtofile/hijack-watcher.git
cd hijack-watcher
cargo build
# built binary should be at: .\target\debug\hijack-watcher.exe
```


## Running
```powershell
cargo run
# Or run the binary directly
hijack-watcher.exe

# Pretty-print JSON Logging
cargo run -- --pretty
./sigstore-watcher --pretty
./sigstore-watcher -p

# Verbose Logging
./sigstore-watcher --verbose
./sigstore-watcher -v

# Custom ETW Session name
./sigstore-watcher --name CustomETWSessionName
./sigstore-watcher -n CustomETWSessionName
```


## Stopping
When the process is killed, the ETW Session should also stop.
But sometimes this doesn't happen so if it does run:
```powershell
logman stop HijackWatcher -ets
```

## Thanks
 - [@daladim](https://github.com/daladim) and [@n4r1b](https://twitter.com/n4r1B) for the FerrisETW Library

## Refrences
 - [FerrisETW](https://github.com/n4r1b/ferrisetw/)
 - [ETW Event Structures](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-create)
