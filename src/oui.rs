pub fn mac_str(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

pub const WIFI: &[(&str, &str)] = &[
    ("00:02:6f", "EnGenius/Senao"),
    ("00:0b:86", "Aruba"),
    ("00:18:0a", "Cisco Meraki"),
    ("00:24:6c", "Aruba"),
    ("00:40:96", "Cisco Aironet"),
    ("00:07:0d", "Cisco Aironet"),
    ("20:4c:03", "Aruba"),
    ("20:aa:4b", "Ruckus"),
    ("24:5a:4c", "Ubiquiti"),
    ("24:a4:3c", "Ubiquiti"),
    ("24:de:c6", "Aruba"),
    ("44:d9:e7", "Ubiquiti"),
    ("50:c7:bf", "TP-Link"),
    ("50:d4:f7", "TP-Link"),
    ("58:97:1e", "Cisco Aironet"),
    ("5c:e9:31", "Ubiquiti"),
    ("68:d7:9a", "Ubiquiti"),
    ("6c:f3:11", "Aruba"),
    ("70:6d:15", "Cisco Aironet"),
    ("74:ac:b9", "Ubiquiti"),
    ("78:8a:20", "Ubiquiti"),
    ("78:8a:20", "Ubiquiti"),
    ("80:2a:a8", "Ubiquiti"),
    ("9c:05:d6", "Ubiquiti"),
    ("b4:fb:e4", "Ubiquiti"),
    ("d0:21:f9", "Ubiquiti"),
    ("dc:9f:db", "Ubiquiti"),
    ("e0:63:da", "Ubiquiti"),
    ("f0:9f:c2", "Ubiquiti"),
    ("fc:ec:da", "Ubiquiti"),
    ("60:b7:6e", "Google Wifi"),
    ("f4:f5:d8", "Google Wifi"),
    ("30:fd:38", "Google Wifi"),
    ("a4:2b:b0", "TP-Link"),
    ("30:b5:c2", "TP-Link"),
    ("c0:25:e9", "TP-Link"),
    ("04:18:d6", "Ubiquiti EdgeMAX"),
    ("48:8f:5a", "MikroTik"),
    ("64:d1:54", "MikroTik"),
    ("b8:69:f4", "MikroTik"),
    ("cc:2d:e0", "MikroTik"),
    ("dc:2c:6e", "MikroTik"),
    ("e4:8d:8c", "MikroTik"),
    ("00:05:85", "Juniper"),
];

pub const ROUTERS: &[(&str, &str)] = &[
    ("04:18:d6", "Ubiquiti EdgeMAX"),
    ("48:8f:5a", "MikroTik"),
    ("64:d1:54", "MikroTik"),
    ("b8:69:f4", "MikroTik"),
    ("cc:2d:e0", "MikroTik"),
    ("dc:2c:6e", "MikroTik"),
    ("e4:8d:8c", "MikroTik"),
    ("00:05:85", "Juniper"),
    ("00:1b:0c", "HPE/Aruba switch"),
    ("00:1f:fe", "HPE ProCurve"),
    ("00:26:99", "Cisco"),
    ("00:1d:a1", "Cisco"),
    ("00:1e:14", "Cisco"),
    ("00:22:bd", "Cisco"),
    ("00:23:04", "Cisco"),
    ("00:25:45", "Cisco"),
];

fn lookup(table: &'static [(&'static str, &'static str)], mac: &[u8; 6]) -> Option<&'static str> {
    let prefix = format!("{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2]);
    for (p, name) in table {
        if *p == prefix {
            return Some(name);
        }
    }
    None
}

pub fn wifi_vendor(mac: &[u8; 6]) -> Option<&'static str> {
    lookup(WIFI, mac)
}

pub fn router_vendor(mac: &[u8; 6]) -> Option<&'static str> {
    lookup(ROUTERS, mac)
}
