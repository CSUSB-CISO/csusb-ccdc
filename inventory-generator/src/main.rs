use clap::{arg as carg, command, value_parser};
use libc::{self, c_int};
use rust_xlsxwriter::{Format, FormatAlign, FormatBorder, Workbook};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{
    ffi::{CStr, CString},
    fs::{self, create_dir_all},
    path::Path,
};

#[derive(Debug, Serialize, Deserialize)]
struct Process {
    name: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Port {
    port: Option<i32>,
    state: Option<String>,
    process: Option<Process>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Connection {
    #[serde(rename = "localAddress")]
    local_address: Option<String>,
    state: Option<String>,
    process: Option<Process>,
}
#[derive(Debug, Serialize, Deserialize)]
struct InventoryData {
    hostname: Option<String>,
    ip: Option<String>,
    os: Option<String>,
    ports: Option<Vec<Port>>,
    connections: Option<Vec<Connection>>,
}
#[derive(Debug, Clone)]
struct HostData {
    hostname: String,
    ip: String,
    os_version: String,
    ports: Vec<String>,
    services: Vec<String>,
}

macro_rules! define_service_ranges {
    ($($range_name:expr => ($start:expr, $end:expr)),*) => {
        fn is_in_range(port: i32, name: &str) -> bool {
            match name {
                $($range_name => port >= $start && port <= $end,)*
                _ => false
            }
        }
    }
}

macro_rules! define_port_mappings {
    ($($port:expr => $service:expr),*) => {
        fn get_service(port: i32) -> Option<&'static str> {
            match port {
                $($port => Some($service),)*
                _ => None
            }
        }
    }
}

macro_rules! define_process_hints {
    ($($pattern:expr => $service:expr),*) => {
        fn get_process_hint(name: &str) -> Option<&'static str> {
            let proc = name.to_lowercase();
            $(if proc.contains($pattern) { return Some($service); })*
            None
        }
    }
}

define_service_ranges! {
   "dynamic-rpc" => (49152, 65535),
   "ephemeral-windows" => (49152, 65535),
   "mssql-dynamic" => (49152, 50152),
   "ephemeral-linux" => (32768, 61000),
   "ephemeral-bsd" => (1024, 5000)
}

// Define common ports
define_port_mappings! {
   7 => "echo",
   9 => "discard",
   13 => "daytime",
   17 => "qotd",
   19 => "chargen",
   20 => "ftp-data",
   21 => "ftp",
   22 => "ssh",
   23 => "telnet",
   25 => "smtp",
   37 => "time",
   42 => "nameserver",
   43 => "whois",
   53 => "domain",
   67 => "bootps",
   68 => "bootpc",
   69 => "tftp",
   80 => "http",
   88 => "kerberos",
   109 => "pop2",
   110 => "pop3",
   111 => "sunrpc",
   113 => "auth",
   119 => "nntp",
   123 => "ntp",
   135 => "msrpc",
   137 => "netbios-ns",
   138 => "netbios-dgm",
   139 => "netbios-ssn",
   143 => "imap",
   161 => "snmp",
   162 => "snmptrap",
   179 => "bgp",
   389 => "ldap",
   427 => "svrloc",
   443 => "https",
   445 => "microsoft-ds",
   464 => "kpasswd",
   465 => "submissions",
   500 => "isakmp",
   512 => "exec",
   513 => "login",
   514 => "shell",
   515 => "printer",
   520 => "route",
   548 => "afpovertcp",
   554 => "rtsp",
   587 => "submission",
   593 => "http-rpc-epmap",
   631 => "ipp",
   636 => "ldaps",
   666 => "doom",
   989 => "ftps-data",
   990 => "ftps",
   993 => "imaps",
   995 => "pop3s",
   1433 => "ms-sql-s",
   1434 => "ms-sql-m",
   1701 => "l2tp",
   1723 => "pptp",
   1801 => "msmq",
   2049 => "nfs",
   2082 => "cpanel",
   2083 => "cpanel-ssl",
   2086 => "whm",
   2087 => "whm-ssl",
   2095 => "webmail",
   2096 => "webmail-ssl",
   3268 => "msft-gc",
   3269 => "msft-gc-ssl",
   3306 => "mysql",
   3389 => "ms-wbt-server",
   3396 => "novell-ipx-cmd",
   4022 => "f5-pvst-port",
   5432 => "postgresql",
   5671 => "amqps",
   5672 => "amqp",
   5900 => "vnc",
   5985 => "wsman",
   5986 => "wsmans",
   6379 => "redis",
   8080 => "http-alt",
   8443 => "https-alt",
   9090 => "zeus-admin",
   9091 => "zeus-admin-ssl",
   9100 => "jetdirect",
   9200 => "elasticsearch",
   9300 => "elasticsearch-nodes",
   9418 => "git",
   11211 => "memcached",
   27017 => "mongodb",
   27018 => "mongodb-shard",
   27019 => "mongodb-config",
   28017 => "mongodb-web"
}

// Define process hints
define_process_hints! {
   "system" => "system",
   "lsass.exe" => "lsass",
   "services.exe" => "services",
   "svchost.exe" => "svchost",
   "spoolsv.exe" => "spooler",
   "wininit.exe" => "wininit",
   "csrss.exe" => "csrss",
   "smss.exe" => "smss",
   "smbd" => "smb",
   "sshd" => "ssh",
   "httpd" => "http",
   "mysqld" => "mysql",
   "ntpd" => "ntp",
   "named" => "domain",
   "postfix" => "smtp",
   "msrpc" => "msrpc",
   "netbios" => "netbios-ssn",
   "microsoft-ds" => "microsoft-ds",
   "dns" => "domain",
   "kerberos" => "kerberos",
   "ldap" => "ldap",
   "rpc" => "msrpc",
   "winrm" => "winrm",
   "wmi" => "wmi",
   "postgres" => "postgresql",
   "mongod" => "mongodb",
   "redis" => "redis",
   "memcached" => "memcached",
   "elasticsearch" => "elasticsearch",
   "nginx" => "http",
   "apache" => "http",
   "rdp" => "rdp",
   "remote-admin" => "remote-admin",
   "remoting" => "remoting",
   "powershell" => "powershell"
}

unsafe fn lookup_service(port: i32, proto: &str) -> Option<String> {
    let proto_c = (!proto.is_empty())
        .then(|| CString::new(proto).ok())
        .flatten()
        .map_or(std::ptr::null(), |s| s.as_ptr());
    (!libc::getservbyport(port.to_be() as c_int, proto_c).is_null())
        .then(|| CStr::from_ptr((*libc::getservbyport(port.to_be() as c_int, proto_c)).s_name))
        .and_then(|s| s.to_str().ok())
        .map(String::from)
}

fn get_service_name(port: i32, process_name: Option<&str>) -> String {
    process_name
        .and_then(get_process_hint)
        .map(|s| s.to_string()) // Convert &'static str to String
        .or_else(|| get_service(port).map(|s| s.to_string())) // Convert &'static str to String
        .or_else(|| {
            ["tcp", "udp", ""]
                .iter()
                .find_map(|p| unsafe { lookup_service(port, p) })
        })
        .map_or_else(
            || {
                if port > 49152 {
                    ["dynamic-rpc", "ephemeral-windows", "mssql-dynamic"]
                        .iter()
                        .find(|&&name| is_in_range(port, name))
                        .map_or("unknown", |&s| s)
                        .to_string() // Convert &'static str to String
                } else {
                    "unknown".to_string() // Convert &'static str to String
                }
            },
            |s| s, // Already a String, no conversion needed
        )
}

fn analyze_services(data: &InventoryData) -> Vec<(i32, String)> {
    let mut services = Vec::new();

    if let Some(ports) = &data.ports {
        services.extend(ports.iter().filter_map(|p| match (&p.port, &p.state) {
            (Some(port), Some(state)) if state == "listen" => Some((
                *port,
                get_service_name(*port, p.process.as_ref().and_then(|p| p.name.as_deref())),
            )),
            _ => None,
        }));
    }

    if let Some(conns) = &data.connections {
        let new_services: Vec<_> = conns
            .iter()
            .filter_map(|c| match (&c.local_address, &c.state) {
                (Some(addr), Some(state)) if state == "listen" => addr
                    .split(':')
                    .last()
                    .and_then(|p| p.parse::<i32>().ok())
                    .filter(|&port| !services.iter().any(|(p, _)| *p == port))
                    .map(|port| {
                        (
                            port,
                            get_service_name(
                                port,
                                c.process.as_ref().and_then(|p| p.name.as_deref()),
                            ),
                        )
                    }),
                _ => None,
            })
            .collect();
        services.extend(new_services);
    }

    services.sort_by_key(|(port, _)| *port);
    services
}

fn extract_host_data(data: InventoryData) -> HostData {
    let (ports, services) = analyze_services(&data)
        .into_iter()
        .map(|(port, service)| (port.to_string(), service))
        .unzip();

    HostData {
        hostname: data.hostname.unwrap_or_default(),
        ip: data.ip.unwrap_or_default(),
        os_version: data.os.unwrap_or_default(),
        ports,
        services,
    }
}

fn create_inventory_report(
    hosts: &[HostData],
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();

    let header_fmt = Format::new()
        .set_background_color(0x4472C4)
        .set_font_color(0xFFFFFF)
        .set_bold()
        .set_border(FormatBorder::Thin)
        .set_text_wrap();

    [25.0, 20.0, 40.0, 60.0, 60.0]
        .iter()
        .enumerate()
        .for_each(|(i, w)| {
            let _ = ws.set_column_width(i as u16, *w);
        });

    [
        "Hostname",
        "IP Address",
        "OS Version",
        "Open Ports",
        "Services",
    ]
    .iter()
    .enumerate()
    .for_each(|(i, h)| {
        let _ = ws.write_with_format(0, i as u16, *h, &header_fmt);
    });

    let mut sorted = hosts.to_vec();
    sorted.sort_by_key(|h| h.hostname.to_lowercase());

    for (i, host) in sorted.iter().enumerate() {
        let row = (i + 1) as u32;
        let fmt = Format::new()
            .set_background_color(if i % 2 == 1 { 0xD9E1F2 } else { 0xEDEDED })
            .set_border(FormatBorder::Thin)
            .set_text_wrap()
            .set_align(FormatAlign::Top);

        [
            &host.hostname,
            &host.ip,
            &host.os_version,
            &host.ports.join(", "),
            &host.services.join(", "),
        ]
        .iter()
        .enumerate()
        .for_each(|(j, v)| {
            let _ = ws.write_with_format(row, j as u16, *v, &fmt);
        });
    }

    if let Some(parent) = Path::new(output).parent() {
        create_dir_all(parent)?;
    }
    wb.save(output)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = command!()
        .arg(
            carg!(-i --input <INPUT_DIR>)
                .required(true)
                .help("Directory containing inventory JSON files")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            carg!(-o --output <OUTPUT_FILE>)
                .required(false)
                .help("Output Excel file path")
                .default_value("network_inventory.xlsx")
                .value_parser(value_parser!(PathBuf)),
        )
        .get_matches();

    let input_dir = matches.get_one::<PathBuf>("input").unwrap();
    let output_file = matches.get_one::<PathBuf>("output").unwrap();

    let hosts = std::fs::read_dir(input_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok()) // Fixed this line
        .filter_map(|c| serde_json::from_str(&c).ok())
        .map(extract_host_data)
        .collect::<Vec<_>>();

    if hosts.is_empty() {
        println!("No inventory files found in {}", input_dir.display());
        return Ok(());
    }

    create_inventory_report(&hosts, output_file.to_str().unwrap())?;
    println!(
        "Inventory report generated successfully with {} hosts.",
        hosts.len()
    );
    Ok(())
}
