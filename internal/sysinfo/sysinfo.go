// Package sysinfo gathers lightweight static facts about the host system for
// use by key-daemon's targeting rules.
package sysinfo

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// Info holds the host attributes that targeting rules can match against.
type Info struct {
	Hostname string
	OSID     string
	Addrs    []net.IP
}

// Gather collects the current host's hostname, OS ID, and non-loopback IP
// addresses. Errors are non-fatal; missing fields simply become empty.
func Gather() (Info, error) {
	var info Info
	var err error

	info.Hostname, err = os.Hostname()
	if err != nil {
		info.Hostname = ""
	}

	info.OSID = readOSID()
	info.Addrs, err = localAddrs()
	if err != nil {
		info.Addrs = nil
	}

	return info, nil
}

func readOSID() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		}
	}
	return ""
}

func localAddrs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, iface := range ifaces {
		// Skip interfaces that are down or loopback.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.IsLoopback() {
				continue
			}
			ips = append(ips, ipnet.IP)
		}
	}
	return ips, nil
}
