// Package target evaluates per-user targeting rules against the current host.
package target

import (
	"fmt"
	"net"
	"path"
	"strings"

	"github.com/matthewgall/key-daemon/internal/sysinfo"
)

// Rule describes the host attributes a user entry must match.
type Rule struct {
	Hostname string `yaml:"hostname"`
	OS       string `yaml:"os"`
	IP       string `yaml:"ip"`
	PublicIP string `yaml:"public_ip"`
}

// Active reports whether the rule contains any conditions.
func (r Rule) Active() bool {
	return r.Hostname != "" || r.OS != "" || r.IP != "" || r.PublicIP != ""
}

// Validate checks that the rule's conditions are syntactically valid.
func (r Rule) Validate() error {
	if r.IP != "" {
		if _, _, err := net.ParseCIDR(r.IP); err != nil {
			return fmt.Errorf("invalid target ip %q: %w", r.IP, err)
		}
	}
	if r.PublicIP != "" {
		if _, _, err := net.ParseCIDR(r.PublicIP); err != nil {
			return fmt.Errorf("invalid target public_ip %q: %w", r.PublicIP, err)
		}
	}
	if r.Hostname != "" {
		if _, err := path.Match(strings.ToLower(r.Hostname), ""); err != nil {
			return fmt.Errorf("invalid target hostname pattern %q: %w", r.Hostname, err)
		}
	}
	return nil
}

// Match returns true when the host described by info satisfies every
// non-empty condition in the rule.
func (r Rule) Match(info sysinfo.Info) (bool, error) {
	if !r.Active() {
		return true, nil
	}

	if r.Hostname != "" && !globMatch(r.Hostname, info.Hostname) {
		return false, nil
	}

	if r.OS != "" && !globMatch(r.OS, info.OSID) {
		return false, nil
	}

	if r.IP != "" {
		_, ipnet, err := net.ParseCIDR(r.IP)
		if err != nil {
			return false, fmt.Errorf("parse target ip %q: %w", r.IP, err)
		}
		if !containsIP(info.Addrs, ipnet) {
			return false, nil
		}
	}

	if r.PublicIP != "" {
		_, ipnet, err := net.ParseCIDR(r.PublicIP)
		if err != nil {
			return false, fmt.Errorf("parse target public_ip %q: %w", r.PublicIP, err)
		}
		if !containsIP([]net.IP{info.ExternalIP}, ipnet) {
			return false, nil
		}
	}

	return true, nil
}

func globMatch(pattern, value string) bool {
	matched, _ := path.Match(strings.ToLower(pattern), strings.ToLower(value))
	return matched
}

func containsIP(addrs []net.IP, network *net.IPNet) bool {
	for _, ip := range addrs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
