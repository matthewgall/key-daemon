package target

import (
	"net"
	"testing"

	"github.com/matthewgall/key-daemon/internal/sysinfo"
)

func TestRuleMatch(t *testing.T) {
	info := sysinfo.Info{
		Hostname: "web-eu-01",
		OSID:     "ubuntu",
		Addrs:    []net.IP{net.ParseIP("10.0.1.5")},
	}

	tests := []struct {
		name    string
		rule    Rule
		want    bool
		wantErr bool
	}{
		{
			name: "empty rule matches",
			rule: Rule{},
			want: true,
		},
		{
			name: "hostname exact match",
			rule: Rule{Hostname: "web-eu-01"},
			want: true,
		},
		{
			name: "hostname glob match",
			rule: Rule{Hostname: "web-*"},
			want: true,
		},
		{
			name: "hostname no match",
			rule: Rule{Hostname: "db-*"},
			want: false,
		},
		{
			name: "os match",
			rule: Rule{OS: "ubuntu"},
			want: true,
		},
		{
			name: "os no match",
			rule: Rule{OS: "debian"},
			want: false,
		},
		{
			name: "ip cidr match",
			rule: Rule{IP: "10.0.0.0/8"},
			want: true,
		},
		{
			name: "ip cidr no match",
			rule: Rule{IP: "192.168.0.0/16"},
			want: false,
		},
		{
			name: "all conditions match",
			rule: Rule{Hostname: "web-*", OS: "ubuntu", IP: "10.0.0.0/8"},
			want: true,
		},
		{
			name: "all conditions one fails",
			rule: Rule{Hostname: "web-*", OS: "debian", IP: "10.0.0.0/8"},
			want: false,
		},
		{
			name: "case insensitive hostname",
			rule: Rule{Hostname: "WEB-EU-01"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.rule.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			got, err := tt.rule.Match(info)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Match error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicIPMatch(t *testing.T) {
	info := sysinfo.Info{
		ExternalIP: net.ParseIP("203.0.113.42"),
	}

	ok, err := (Rule{PublicIP: "203.0.113.0/24"}).Match(info)
	if err != nil || !ok {
		t.Errorf("expected match, got ok=%v err=%v", ok, err)
	}

	ok, err = (Rule{PublicIP: "198.51.100.0/24"}).Match(info)
	if err != nil || ok {
		t.Errorf("expected no match, got ok=%v err=%v", ok, err)
	}

	// No external IP gathered -> fail closed.
	ok, err = (Rule{PublicIP: "203.0.113.0/24"}).Match(sysinfo.Info{})
	if err != nil || ok {
		t.Errorf("expected no match when external IP missing, got ok=%v err=%v", ok, err)
	}
}

func TestRuleValidate(t *testing.T) {
	if err := (Rule{IP: "not-a-cidr"}).Validate(); err == nil {
		t.Error("expected error for invalid CIDR")
	}
	if err := (Rule{PublicIP: "not-a-cidr"}).Validate(); err == nil {
		t.Error("expected error for invalid public_ip CIDR")
	}
	if err := (Rule{Hostname: "[bad"}).Validate(); err == nil {
		t.Error("expected error for invalid hostname pattern")
	}
}
