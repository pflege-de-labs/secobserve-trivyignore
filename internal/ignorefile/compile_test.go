package ignorefile

import (
	"os"
	"testing"

	"github.com/pflege-de-labs/secobserve-trivyignore/internal/secobserve"
)

const base = "https://so"

func str(s string) *string { return &s }

func obs(id int, status, vuln, purl string, expiry *string, aliases ...string) secobserve.Observation {
	o := secobserve.Observation{ID: id, CurrentStatus: status, VulnerabilityID: vuln, OriginComponentPURL: purl, RiskAcceptanceExpiryDate: expiry}
	for _, a := range aliases {
		o.VulnerabilityIDAliases = append(o.VulnerabilityIDAliases, secobserve.Alias{Alias: a})
	}
	return o
}

func TestCompileBasic(t *testing.T) {
	r := Compile([]secobserve.Observation{obs(9, "False positive", "CVE-2025-1", "pkg:golang/a@v1", nil)}, base+"/")
	if len(r.File.Vulnerabilities) != 1 {
		t.Fatalf("got %d entries", len(r.File.Vulnerabilities))
	}
	e := r.File.Vulnerabilities[0]
	if e.ExpiredAt != "" || e.Statement != "False positive — https://so/#/observations/9/show" {
		t.Errorf("unexpected entry %+v", e)
	}
}

func TestCompileAliases(t *testing.T) {
	r := Compile([]secobserve.Observation{obs(1, "Not affected", "CVE-2025-1", "pkg:golang/a@v1", nil, "GHSA-x", "CVE-2025-1", "")}, base)
	v := r.File.Vulnerabilities
	if len(v) != 2 || v[0].ID != "CVE-2025-1" || v[1].ID != "GHSA-x" || v[0].PURLs[0] != v[1].PURLs[0] {
		t.Errorf("unexpected entries %+v", v)
	}
}

func TestCompileRiskAcceptedExpiry(t *testing.T) {
	r := Compile([]secobserve.Observation{obs(1, "Risk accepted", "CVE-1", "pkg:a", str("2027-01-19"))}, base)
	if got := r.File.Vulnerabilities[0].ExpiredAt; got != "2027-01-19" {
		t.Errorf("ExpiredAt = %q", got)
	}
	r = Compile([]secobserve.Observation{obs(1, "False positive", "CVE-1", "pkg:a", str("2027-01-19"))}, base)
	if got := r.File.Vulnerabilities[0].ExpiredAt; got != "" {
		t.Errorf("non-risk-accepted ExpiredAt = %q", got)
	}
}

func TestCompileSkipsMissingPurl(t *testing.T) {
	r := Compile([]secobserve.Observation{obs(1, "False positive", "CVE-1", "", nil), obs(2, "False positive", "", "pkg:a", nil)}, base)
	if len(r.File.Vulnerabilities) != 0 || r.SkippedNoPURL != 1 {
		t.Errorf("got %+v", r)
	}
}

func TestCompileDedupKeepsLongestValidity(t *testing.T) {
	r := Compile([]secobserve.Observation{
		obs(1, "Risk accepted", "CVE-1", "pkg:a", str("2027-01-19")),
		obs(2, "False positive", "CVE-1", "pkg:a", nil),
	}, base)
	if len(r.File.Vulnerabilities) != 1 || r.File.Vulnerabilities[0].ExpiredAt != "" {
		t.Errorf("got %+v", r.File.Vulnerabilities)
	}
	r = Compile([]secobserve.Observation{
		obs(1, "Risk accepted", "CVE-1", "pkg:a", str("2027-01-19")),
		obs(2, "Risk accepted", "CVE-1", "pkg:a", str("2027-03-01")),
	}, base)
	if len(r.File.Vulnerabilities) != 1 || r.File.Vulnerabilities[0].ExpiredAt != "2027-03-01" {
		t.Errorf("got %+v", r.File.Vulnerabilities)
	}
}

func TestMarshalEmpty(t *testing.T) {
	b, err := Compile(nil, base).File.Marshal()
	if err != nil || string(b) != "vulnerabilities: []\n" {
		t.Errorf("got %q, %v", b, err)
	}
}

func TestMarshalGolden(t *testing.T) {
	r := Compile([]secobserve.Observation{
		obs(3, "Risk accepted", "CVE-2025-2", "pkg:maven/b/c@1?type=jar", str("2027-01-19")),
		obs(9, "False positive", "CVE-2025-1", "pkg:golang/a@v1", nil, "GHSA-x"),
		obs(4, "Not security", "CVE-2025-1", "pkg:golang/a@v0", nil),
	}, base)
	got, err := r.File.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/golden.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestCompileIgnoresNonSuppressingStatus(t *testing.T) {
	r := Compile([]secobserve.Observation{
		obs(1, "Open", "CVE-2025-1", "pkg:golang/a@v1", nil),
		obs(2, "Affected", "CVE-2025-2", "pkg:golang/a@v1", nil),
		obs(3, "In review", "CVE-2025-3", "pkg:golang/a@v1", nil),
	}, base)
	if len(r.File.Vulnerabilities) != 0 {
		t.Fatalf("got %+v", r.File.Vulnerabilities)
	}
}
