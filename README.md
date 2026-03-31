wf is a terminal-first macOS tool for bypassing captive portals on open
Wi-Fi networks. It also includes a small network scanner for discovering
candidate client MAC addresses on the current subnet.

The codebase is a single-file Go CLI in `main.go`.

## Build
```sh
go build -o wf .
```

```sh
./wf help
```

You can also run it directly:

```sh
go run . help
```

## Usage
```sh
sudo ./wf bypass
```

Commands:

- `sudo ./wf bypass [--silent]`
- `sudo ./wf scan`
- `sudo ./wf reset`
- `./wf list`
- `./wf status`
- `./wf help`
- `./wf help <command>`

Examples:

```sh
./wf status
./wf help bypass
sudo ./wf scan
sudo ./wf bypass --silent
```

Typical flow:

1. Connect to an open Wi-Fi network. WEP, WPA, and WPA2 are not supported.
2. Run `./wf status` to confirm the network is open and internet access is
   still blocked.
3. Run `sudo ./wf bypass`.
4. If needed, run `./wf list` to inspect candidate client MAC addresses or
   `sudo ./wf scan` to refresh the ARP table.
5. Run `sudo ./wf reset` when you want to restore the hardware MAC address.

## How It Works
wf automates a MAC-spoofing workflow:

1. Discover other connected clients from the ARP table, optionally
   primed by a subnet ping scan.
2. Clone discovered MAC addresses in sequence.
3. Reconnect to the current open network after each spoofed address.
4. Test connectivity by requesting a known success page.

The implementation is macOS-only and shells out to native tools such as
`networksetup`, `ifconfig`, `arp`, `ping`, `netstat`, and `ipconfig`.

## Disclaimer
Only use this software on networks you own or have permission to use.
