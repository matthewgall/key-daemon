// Package sysinfo gathers lightweight static facts about the host system for
// use by key-daemon's targeting rules.
package sysinfo

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Info holds the host attributes that targeting rules can match against.
type Info struct {
	Hostname   string
	OSID       string
	Addrs      []net.IP
	ExternalIP net.IP
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

// FetchExternalIP returns the host's public IP by asking the given HTTPS
// endpoint. The endpoint may return either the IP as plain text or a JSON
// object containing an "ip" field (e.g. https://ipinfo.io/).
func FetchExternalIP(ctx context.Context, client *http.Client, url string) (net.IP, error) {
	if url == "" {
		return nil, nil
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("external IP endpoint returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}

	s := strings.TrimSpace(string(data))
	if strings.HasPrefix(s, "{") {
		var result struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal([]byte(s), &result); err != nil {
			return nil, fmt.Errorf("parse external IP JSON response: %w", err)
		}
		s = strings.TrimSpace(result.IP)
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("could not parse external IP %q", s)
	}
	return ip, nil
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
