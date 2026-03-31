package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	blockSize   = 255
	successURL  = "http://www.apple.com/library/test/success.html"
	successBody = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
)

type routeContext struct {
	Gateway   string
	Interface string
}

type wifiConnection struct {
	Iface    string
	SSID     string
	Security string
}

type hardwarePort struct {
	Port           string
	Device         string
	Address        string
	CurrentAddress string
}

type systemProfilerAirport struct {
	SPAirPortDataType []struct {
		Interfaces []struct {
			Name              string `json:"_name"`
			StatusInformation string `json:"spairport_status_information"`
			CurrentNetwork    struct {
				Name         string `json:"_name"`
				SecurityMode string `json:"spairport_security_mode"`
			} `json:"spairport_current_network_information"`
		} `json:"spairport_airport_interfaces"`
	} `json:"SPAirPortDataType"`
}

var macAddressRe = regexp.MustCompile(`(?i)^([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}$`)

type commandSpec struct {
	Name        string
	UsageLine   string
	Description string
}

var commandSpecs = []commandSpec{
	{
		Name:        "bypass",
		UsageLine:   "sudo wf bypass [--silent]",
		Description: "Attempt captive portal bypass by cycling MAC addresses.",
	},
	{
		Name:        "scan",
		UsageLine:   "sudo wf scan",
		Description: "Ping the local subnet to populate the ARP table.",
	},
	{
		Name:        "reset",
		UsageLine:   "sudo wf reset",
		Description: "Restore the interface MAC address to its hardware value.",
	},
	{
		Name:        "list",
		UsageLine:   "wf list",
		Description: "Print candidate client MAC addresses on the current network.",
	},
	{
		Name:        "status",
		UsageLine:   "wf status",
		Description: "Print whether the Wi-Fi is open and internet access works.",
	},
	{
		Name:        "help",
		UsageLine:   "wf help [command]",
		Description: "Show global help or per-command usage.",
	},
}

type exitError struct {
	message string
	code    int
}

func (e *exitError) Error() string {
	return e.message
}

func main() {
	if runtimeErr := run(os.Args[1:]); runtimeErr != nil {
		var cliExit *exitError
		if errors.As(runtimeErr, &cliExit) {
			fail(cliExit.message, cliExit.code)
		}
		fail(runtimeErr.Error(), 1)
	}
}

func run(args []string) error {
	command := "help"
	commandArgs := args
	if len(args) > 0 {
		command = args[0]
		commandArgs = args[1:]
	}

	switch command {
	case "bypass":
		fs := newFlagSet("bypass")
		silentMode := fs.Bool(
			"silent",
			false,
			"skip the active scan and only use discovered MACs",
		)
		if err := parseCommandFlags(fs, commandArgs); err != nil {
			return err
		}
		if err := rejectUnexpectedArgs(fs, "bypass"); err != nil {
			return err
		}
		requireRoot()
		fmt.Printf(
			"Starting bypass%s...\n",
			map[bool]string{true: " in silent mode"}[*silentMode],
		)
		if err := connect(*silentMode); err != nil {
			return err
		}
		fmt.Println("Bypass complete.")
		return nil
	case "scan":
		fs := newFlagSet("scan")
		if err := parseCommandFlags(fs, commandArgs); err != nil {
			return err
		}
		if err := rejectUnexpectedArgs(fs, "scan"); err != nil {
			return err
		}
		requireRoot()
		fmt.Println("Scanning local subnet...")
		if err := manualScan(); err != nil {
			return err
		}
		fmt.Println("Scan complete.")
		return nil
	case "reset":
		fs := newFlagSet("reset")
		if err := parseCommandFlags(fs, commandArgs); err != nil {
			return err
		}
		if err := rejectUnexpectedArgs(fs, "reset"); err != nil {
			return err
		}
		requireRoot()
		if err := reset(); err != nil {
			return err
		}
		fmt.Println("Restored the hardware MAC address.")
		return nil
	case "list":
		fs := newFlagSet("list")
		if err := parseCommandFlags(fs, commandArgs); err != nil {
			return err
		}
		if err := rejectUnexpectedArgs(fs, "list"); err != nil {
			return err
		}
		return printValidMACs()
	case "status":
		fs := newFlagSet("status")
		if err := parseCommandFlags(fs, commandArgs); err != nil {
			return err
		}
		if err := rejectUnexpectedArgs(fs, "status"); err != nil {
			return err
		}
		return printStatus()
	case "help", "--help", "-h":
		return printHelp(commandArgs)
	default:
		return fmt.Errorf(
			"unknown command: %s\n\n%s",
			command,
			globalUsage(),
		)
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseCommandFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return &exitError{
				message: commandUsage(fs.Name()),
				code:    0,
			}
		}
		return fmt.Errorf("%v\n\n%s", err, commandUsage(fs.Name()))
	}
	return nil
}

func rejectUnexpectedArgs(fs *flag.FlagSet, command string) error {
	if fs.NArg() == 0 {
		return nil
	}
	return fmt.Errorf(
		"unexpected arguments: %s\n\n%s",
		strings.Join(fs.Args(), " "),
		commandUsage(command),
	)
}

func globalUsage() string {
	var b strings.Builder
	b.WriteString("wf CLI\n\n")
	b.WriteString("Usage:\n")
	b.WriteString("  wf <command> [options]\n\n")
	b.WriteString("Commands:\n")
	for _, spec := range commandSpecs {
		fmt.Fprintf(
			&b,
			"  %-7s %s\n",
			spec.Name,
			spec.Description,
		)
	}
	b.WriteString("\n")
	b.WriteString("Run `wf help <command>` for command-specific usage.")
	return b.String()
}

func commandUsage(command string) string {
	spec, ok := findCommandSpec(command)
	if !ok {
		return globalUsage()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Usage:\n  %s\n\n", spec.UsageLine)
	b.WriteString(spec.Description)

	switch command {
	case "bypass":
		b.WriteString("\n\nOptions:\n")
		b.WriteString(
			"  -silent\n" +
				"        skip the active scan and only use discovered MACs",
		)
	case "help":
		b.WriteString("\n\nExamples:\n")
		b.WriteString("  wf help\n")
		b.WriteString("  wf help bypass")
	}

	return b.String()
}

func findCommandSpec(name string) (commandSpec, bool) {
	for _, spec := range commandSpecs {
		if spec.Name == name {
			return spec, true
		}
	}
	return commandSpec{}, false
}

func printHelp(args []string) error {
	if len(args) == 0 {
		fmt.Println(globalUsage())
		return nil
	}
	command := args[0]
	if _, ok := findCommandSpec(command); !ok {
		return fmt.Errorf(
			"unknown help topic: %s\n\n%s",
			command,
			globalUsage(),
		)
	}
	fmt.Println(commandUsage(command))
	return nil
}

func fail(message string, code int) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(code)
}

func requireRoot() {
	if os.Geteuid() != 0 {
		fail("This command must run as root on macOS. Re-run it with sudo.", 1)
	}
}

func printStatus() error {
	fmt.Println("Checking network status...")

	type openNetworkResult struct {
		value bool
		err   error
	}

	openNetworkCh := make(chan openNetworkResult, 1)
	internetAccessCh := make(chan bool, 1)

	go func() {
		onOpenNetwork, err := isOnOpenNetwork()
		openNetworkCh <- openNetworkResult{
			value: onOpenNetwork,
			err:   err,
		}
	}()

	go func() {
		internetAccessCh <- hasInternetAccess()
	}()

	openNetworkResultValue := <-openNetworkCh
	if openNetworkResultValue.err != nil {
		return openNetworkResultValue.err
	}
	hasInternetAccess := <-internetAccessCh
	fmt.Printf(
		"Open Wi-Fi network: %s\n",
		yesNo(openNetworkResultValue.value),
	)
	fmt.Printf("Internet access: %s\n", yesNo(hasInternetAccess))
	return nil
}

func printValidMACs() error {
	macs, err := listValidMACs(nil)
	if err != nil {
		return err
	}
	if len(macs) == 0 {
		fmt.Println("No candidate client MAC addresses found.")
		return nil
	}
	for _, mac := range macs {
		fmt.Println(mac)
	}
	return nil
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func execOutput(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(output))
		if text != "" {
			return "", errors.New(text)
		}
		return "", err
	}
	return string(output), nil
}

func hasInternetAccess() bool {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(successURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	return string(body) == successBody
}

func reconnectToOpenNetwork(iface, ssid string) error {
	_, err := execOutput("/usr/sbin/networksetup",
		"-setairportnetwork", iface, ssid)
	return err
}

func getCurrentConnection() (*wifiConnection, error) {
	if runtime.GOOS != "darwin" {
		return nil, errors.New("wf currently supports macOS only.")
	}

	securityConnection, err := getCurrentConnectionSecurity()
	if err != nil {
		return nil, err
	}
	if securityConnection == nil {
		return nil, nil
	}

	ssid, err := getAirportNetwork(securityConnection.Iface)
	if err != nil {
		return nil, err
	}
	if ssid != "" {
		securityConnection.SSID = ssid
		return securityConnection, nil
	}

	return getCurrentConnectionViaSystemProfiler()
}

func getCurrentConnectionSecurity() (*wifiConnection, error) {
	context, err := getRouteContext()
	if err != nil {
		return nil, err
	}
	if context.Interface == "" {
		return nil, nil
	}

	summary, err := execOutput(
		"/usr/sbin/ipconfig",
		"getsummary",
		context.Interface,
	)
	if err != nil {
		return nil, err
	}
	security := parseSummaryField(summary, "Security")
	if security == "" {
		return nil, nil
	}

	return &wifiConnection{
		Iface:    context.Interface,
		Security: security,
	}, nil
}

func getCurrentConnectionViaSystemProfiler() (*wifiConnection, error) {
	stdout, err := execOutput(
		"/usr/sbin/system_profiler",
		"SPAirPortDataType",
		"-json",
	)
	if err != nil {
		return nil, err
	}

	var payload systemProfilerAirport
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		return nil, err
	}

	for _, item := range payload.SPAirPortDataType {
		for _, iface := range item.Interfaces {
			if iface.StatusInformation != "spairport_status_connected" {
				continue
			}
			return &wifiConnection{
				Iface:    iface.Name,
				SSID:     iface.CurrentNetwork.Name,
				Security: iface.CurrentNetwork.SecurityMode,
			}, nil
		}
	}

	return nil, nil
}

func parseSummaryField(summary, key string) string {
	prefix := key + " : "
	for _, line := range strings.Split(summary, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
		if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
			return ""
		}
		return value
	}
	return ""
}

func getAirportNetwork(hardwarePort string) (string, error) {
	stdout, err := execOutput(
		"/usr/sbin/networksetup",
		"-getairportnetwork",
		hardwarePort,
	)
	if err != nil {
		if strings.Contains(err.Error(), "not associated") {
			return "", nil
		}
		return "", err
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) == 0 {
		return "", nil
	}
	line := lines[len(lines)-1]
	const prefix = "Current Wi-Fi Network: "
	if !strings.HasPrefix(line, prefix) {
		return "", nil
	}
	return strings.TrimSpace(strings.TrimPrefix(line, prefix)), nil
}

func normalizeSecurityMode(securityMode string) string {
	return strings.TrimPrefix(
		strings.ToLower(securityMode),
		"spairport_security_mode_",
	)
}

func isOnOpenNetwork() (bool, error) {
	currentConnection, err := getCurrentConnectionSecurity()
	if err != nil {
		return false, err
	}
	if currentConnection == nil {
		return false, nil
	}
	return normalizeSecurityMode(currentConnection.Security) == "none", nil
}

func getRouteContext() (*routeContext, error) {
	stdout, err := execOutput("/usr/sbin/netstat", "-rn", "-f", "inet")
	if err != nil {
		return nil, err
	}

	releaseParts := strings.Split(osRelease(), ".")
	releaseMajor, _ := strconv.Atoi(releaseParts[0])
	ifaceColumn := 5
	if releaseMajor >= 19 {
		ifaceColumn = 3
	}

	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		columns := strings.Fields(line)
		if len(columns) < 2 {
			continue
		}
		target := columns[0]
		gateway := columns[1]
		if !isDefaultDestination(target) || net.ParseIP(gateway) == nil {
			continue
		}

		iface := ""
		if len(columns) > ifaceColumn {
			iface = columns[ifaceColumn]
		}
		return &routeContext{
			Gateway:   gateway,
			Interface: iface,
		}, nil
	}

	return nil, errors.New("Unable to determine default gateway")
}

func osRelease() string {
	return strings.TrimSpace(runUname())
}

func runUname() string {
	if release, err := execOutput("/usr/bin/uname", "-r"); err == nil {
		return release
	}
	return ""
}

func isDefaultDestination(target string) bool {
	switch target {
	case "default", "0.0.0.0", "0.0.0.0/0", "::", "::/0":
		return true
	default:
		return false
	}
}

func getInterfaceIPv4(name string) (*net.Interface, *net.IPNet, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.To4() == nil {
			continue
		}
		return iface, ipNet, nil
	}
	return nil, nil, fmt.Errorf("no IPv4 address found for interface %s", name)
}

func listValidMACs(context *routeContext) ([]string, error) {
	if context == nil {
		var err error
		context, err = getRouteContext()
		if err != nil {
			return nil, err
		}
	}

	iface, _, err := getInterfaceIPv4(context.Interface)
	if err != nil {
		return nil, err
	}
	currentMAC := strings.ToUpper(normalizeMAC(iface.HardwareAddr.String()))
	macs, err := listARPTableMACs(context.Gateway)
	if err != nil {
		return nil, err
	}

	var valid []string
	for _, mac := range macs {
		if mac == currentMAC || isMulticastAddress(mac) || isBroadcastAddress(mac) {
			continue
		}
		valid = append(valid, mac)
	}
	return valid, nil
}

func listARPTableMACs(gatewayIP string) ([]string, error) {
	stdout, err := execOutput("/usr/sbin/arp", "-a")
	if err != nil {
		return nil, err
	}
	var macs []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		if strings.Trim(parts[1], "()") == gatewayIP {
			continue
		}
		mac := parts[3]
		if mac == "(incomplete)" {
			continue
		}
		macs = append(macs, strings.ToUpper(normalizeMAC(mac)))
	}
	return macs, nil
}

func isMulticastAddress(mac string) bool {
	firstOctet, err := strconv.ParseUint(strings.Split(mac, ":")[0], 16, 8)
	if err != nil {
		return false
	}
	return firstOctet&1 == 1
}

func isBroadcastAddress(mac string) bool {
	return strings.EqualFold(mac, "FF:FF:FF:FF:FF:FF")
}

func pingScan(interfaceName string, blockCallback func() (bool, error)) (bool, error) {
	_, ipNet, err := getInterfaceIPv4(interfaceName)
	if err != nil {
		return false, err
	}
	hostIPs, err := cidrHosts(ipNet.String())
	if err != nil {
		return false, err
	}

	for i := 0; i < len(hostIPs); i += blockSize {
		isConnected, err := blockCallback()
		if err != nil {
			return false, err
		}
		if isConnected {
			return true, nil
		}

		end := i + blockSize
		if end > len(hostIPs) {
			end = len(hostIPs)
		}
		fmt.Println("Scanning next block of", blockSize)
		for _, ip := range hostIPs[i:end] {
			_ = ping(ip)
		}
	}

	fmt.Println("Scan complete.")
	return false, nil
}

func cidrHosts(cidr string) ([]string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	prefix = prefix.Masked()

	bits := prefix.Addr().BitLen()
	ones := prefix.Bits()
	hostBits := bits - ones
	if hostBits >= 31 {
		return nil, fmt.Errorf("CIDR range too large to scan: %s", cidr)
	}
	total := 1 << hostBits
	addr := prefix.Addr()
	var hosts []string

	for i := 0; i < total; i++ {
		hosts = append(hosts, addr.String())
		addr = addr.Next()
	}

	if prefix.Addr().Is4() && ones <= 30 && len(hosts) >= 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

func ping(ip string) error {
	_, err := execOutput("/sbin/ping", "-c", "1", ip)
	return err
}

func manualScan() error {
	context, err := getRouteContext()
	if err != nil {
		return err
	}
	_, err = pingScan(context.Interface, func() (bool, error) {
		return false, nil
	})
	return err
}

func tryMACs(attempted map[string]bool, initialSSID string,
	it *hardwarePort, context *routeContext) (bool, error) {
	newMACs, err := listValidMACs(context)
	if err != nil {
		return false, err
	}

	for _, mac := range newMACs {
		if attempted[mac] {
			continue
		}

		fmt.Println("Trying MAC", mac)
		if err := setInterfaceMAC(it.Device, mac); err != nil {
			return false, err
		}
		attempted[mac] = true

		if err := reconnectToOpenNetwork(it.Device, initialSSID); err != nil {
			return false, err
		}

		if hasInternetAccess() {
			fmt.Println("Connected with MAC", mac)
			return true, nil
		}
	}

	fmt.Println("Done trying block of MACs")
	return false, nil
}

func connect(silentMode bool) error {
	if hasInternetAccess() {
		return nil
	}

	context, err := getRouteContext()
	if err != nil {
		return err
	}
	it, err := findInterface(context.Interface)
	if err != nil {
		return err
	}
	currentConnection, err := getCurrentConnection()
	if err != nil {
		return err
	}
	if currentConnection == nil {
		return errors.New("Not connected to any network.")
	}

	fmt.Println("Network security", currentConnection.Security)
	if normalizeSecurityMode(currentConnection.Security) != "none" {
		fmt.Println(currentConnection.SSID, "is not an open network.")
		return errors.New("wf only works with open networks.")
	}

	iface, _, err := getInterfaceIPv4(context.Interface)
	if err != nil {
		return err
	}
	attempted := map[string]bool{
		strings.ToUpper(normalizeMAC(iface.HardwareAddr.String())): true,
	}

	if silentMode {
		connected, err := tryMACs(attempted, currentConnection.SSID, it, context)
		if err != nil {
			return err
		}
		if connected {
			return nil
		}
	} else {
		connected, err := pingScan(context.Interface, func() (bool, error) {
			return tryMACs(attempted, currentConnection.SSID, it, context)
		})
		if err != nil {
			return err
		}
		if connected {
			return nil
		}
	}

	fmt.Println("Failed to connect with any MAC")
	if len(attempted) > 1 {
		return errors.New("wf couldn't bypass the captive portal.")
	}
	return errors.New("No other users are on this network.")
}

func reset() error {
	context, err := getRouteContext()
	if err != nil {
		return err
	}
	it, err := findInterface(context.Interface)
	if err != nil {
		return err
	}
	return setInterfaceMAC(it.Device, it.Address)
}

func listHardwarePorts() ([]hardwarePort, error) {
	stdout, err := execOutput("/usr/sbin/networksetup", "-listallhardwareports")
	if err != nil {
		return nil, err
	}

	var ports []hardwarePort
	var current *hardwarePort
	for _, line := range strings.Split(stdout, "\n") {
		switch {
		case strings.HasPrefix(line, "Hardware Port: "):
			if current != nil && current.Device != "" {
				ports = append(ports, *current)
			}
			current = &hardwarePort{
				Port: strings.TrimPrefix(line, "Hardware Port: "),
			}
		case current == nil:
			continue
		case strings.HasPrefix(line, "Device: "):
			current.Device = strings.TrimPrefix(line, "Device: ")
		case strings.HasPrefix(line, "Ethernet Address: "):
			addr, err := validateMAC(strings.TrimPrefix(line, "Ethernet Address: "))
			if err == nil {
				current.Address = addr
			}
		}
	}
	if current != nil && current.Device != "" {
		ports = append(ports, *current)
	}
	return ports, nil
}

func findInterface(target string) (*hardwarePort, error) {
	ports, err := listHardwarePorts()
	if err != nil {
		return nil, err
	}
	normalizedTarget := strings.ToLower(target)
	for _, port := range ports {
		if strings.ToLower(port.Device) != normalizedTarget &&
			strings.ToLower(port.Port) != normalizedTarget {
			continue
		}
		port.CurrentAddress, _ = getCurrentMAC(port.Device)
		return &port, nil
	}
	return nil, fmt.Errorf("Unable to find network interface: %s", target)
}

func getCurrentMAC(device string) (string, error) {
	stdout, err := execOutput("/sbin/ifconfig", device)
	if err != nil {
		return "", err
	}
	match := regexp.MustCompile(`(?m)^\s*ether\s+([0-9a-f:]+)$`).FindStringSubmatch(stdout)
	if len(match) < 2 {
		return "", nil
	}
	return validateMAC(match[1])
}

func setInterfaceMAC(device, mac string) error {
	normalizedMAC, err := validateMAC(mac)
	if err != nil {
		return err
	}
	_, err = execOutput("/sbin/ifconfig", device, "ether", normalizedMAC)
	return err
}

func validateMAC(mac string) (string, error) {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"))
	if !macAddressRe.MatchString(normalized) {
		return "", fmt.Errorf("%s is not a valid MAC address", mac)
	}
	parts := strings.Split(normalized, ":")
	for i, part := range parts {
		if len(part) == 1 {
			parts[i] = "0" + part
		}
	}
	return strings.Join(parts, ":"), nil
}

func normalizeMAC(mac string) string {
	normalized, err := validateMAC(mac)
	if err != nil {
		return ""
	}
	return normalized
}
