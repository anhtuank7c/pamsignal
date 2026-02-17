# Journal Subscriber

- **Status**: In Progress
- **Start Date**: 27/12/2025
- **Completion Date**: 

## 1. Objectives

- **Event-driven**: Replace traditional log file scanning with event subscription from `libsystemd`, enabling PAMSignal to react immediately when new logs appear without wasting resources during idle periods.
- **Real-time**: Leverage the `sd_journal_wait()` function to achieve `~0s` latency from when the system records a login session to when PAMSignal begins processing the data.
- **Structured data**: Exploit the binary format of the Journal to accurately retrieve metadata fields such as `MESSAGE`, `_PID`, `_UID`.

## 2. Understanding systemd and journal

Previously, I had an extremely simple idea: scan the `/var/log/auth.log` file and then parse strings to extract login session information. While this could prove the "login alert" concept was feasible, in terms of performance, stability, and reliability, it was not robust.

**Specifically:**

- Processing each log line presents challenges because time formats and message patterns vary significantly across different OS versions, leading to unreliable information extraction.

- Periodic polling every `500ms` wastes resources. In a typical day, there aren't many successful login sessions to the system, so this approach is inefficient.
- If a hacker gains system access and deletes traces in the auth.log file within 500ms, the system would be completely unaware.

A friend in my network, **Nguyễn Hồng Quân**, shared that I should learn about systemd and journal. He mentioned that those log files are just backward compatibility features supporting legacy systems. So I started investigating.

### 2.1 What is systemd?

**systemd** is a modern system and service manager for Linux operating systems. It has become the de facto standard init system for most major Linux distributions, replacing traditional SysV init.

**Core Components:**

- **systemd (PID 1)**: The first process started by the kernel, responsible for initializing the system and managing all other processes
- **systemd-journald**: The logging daemon that collects and stores log data
- **systemctl**: Command-line tool for controlling systemd services
- **journalctl**: Command-line tool for querying and viewing journal logs

**Why systemd matters for PAMSignal:**

systemd provides a unified, modern approach to system management that addresses the limitations of traditional logging:

1. **Centralized Logging**: All system logs (kernel, services, applications) are collected in one place
2. **Binary Format**: Logs are stored in an indexed, structured binary format rather than plain text
3. **Rich Metadata**: Each log entry includes extensive metadata (PID, UID, service name, timestamps, etc.)
4. **Event-Driven API**: Applications can subscribe to log events in real-time via `libsystemd`

### 2.2 systemd-journald Architecture

**How it works:**

```
┌─────────────────────────────────────────────────────────┐
│                    Log Sources                          │
├─────────────┬──────────────┬──────────────┬────────────┤
│   Kernel    │   Services   │  Applications │   Syslog   │
│   (kmsg)    │  (stdout)    │  (sd_journal) │  (legacy)  │
└──────┬──────┴──────┬───────┴──────┬────────┴─────┬──────┘
       │             │              │              │
       └─────────────┴──────────────┴──────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  systemd-journald    │
              │  (Central Collector) │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Binary Journal     │
              │   /var/log/journal/  │
              │   (Indexed, Sealed)  │
              └──────────┬───────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    journalctl      libsystemd      rsyslog
    (Query CLI)     (Event API)     (Forward)
```

**Key Features:**

1. **Structured Storage**: Each log entry is a structured record with key-value pairs
2. **Indexing**: Fast queries using metadata fields (unit, priority, time range)
3. **Tamper-Resistance**: Optional Forward Secure Sealing (FSS) prevents log modification
4. **Automatic Rotation**: Size and time-based rotation with configurable retention
5. **Performance**: Optimized for high-volume logging with minimal overhead

### 2.3 Advantages Over Traditional Log Files

| Feature | Traditional (/var/log/auth.log) | systemd-journald |
|---------|--------------------------------|------------------|
| **Format** | Plain text, unstructured | Binary, structured with metadata |
| **Parsing** | Regex/string parsing (fragile) | Direct field access (reliable) |
| **Performance** | Sequential file scanning | Indexed queries |
| **Real-time** | File polling (500ms+ latency) | Event-driven API (~0ms latency) |
| **Tampering** | Easy to modify/delete | Sealed with cryptographic hashing |
| **Metadata** | Limited (timestamp, message) | Rich (PID, UID, service, hostname, etc.) |
| **Rotation** | Manual logrotate configuration | Automatic with systemd |

### 2.4 libsystemd Event-Driven API

For PAMSignal, the critical advantage is the **event-driven architecture** provided by `libsystemd`:

**Traditional Approach (Polling):**
```c
while (1) {
    read_log_file("/var/log/auth.log");
    parse_new_lines();
    sleep(500); // Waste CPU, miss events
}
```

**systemd Approach (Event-Driven):**
```c
sd_journal *j;
sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
sd_journal_seek_tail(j);

while (1) {
    // Wait for new journal entries (blocking, no CPU waste)
    sd_journal_wait(j, (uint64_t) -1);
    
    // Process new entries immediately
    while (sd_journal_next(j) > 0) {
        const void *data;
        size_t length;
        
        // Direct field access, no parsing needed
        sd_journal_get_data(j, "MESSAGE", &data, &length);
        sd_journal_get_data(j, "_PID", &data, &length);
        sd_journal_get_data(j, "_UID", &data, &length);
    }
}
```

**Key Functions:**

- `sd_journal_open()`: Open the journal for reading
- `sd_journal_wait()`: Block until new entries arrive (event-driven)
- `sd_journal_next()`: Move to the next entry
- `sd_journal_get_data()`: Retrieve specific fields by name
- `sd_journal_add_match()`: Filter entries by criteria (e.g., only auth events)

**Benefits for PAMSignal:**

1. ✅ **Zero polling overhead**: CPU usage only when events occur
2. ✅ **Instant notifications**: ~0ms latency from event to processing
3. ✅ **Reliable parsing**: No regex, direct field access
4. ✅ **Tamper detection**: Sealed logs prevent attacker log deletion
5. ✅ **Cross-distro compatibility**: Works on all systemd-based distributions

This architecture makes PAMSignal a truly real-time, efficient, and reliable authentication monitoring solution.
