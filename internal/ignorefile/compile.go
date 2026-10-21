// Package ignorefile compiles SecObserve observations into a Trivy .trivyignore.yaml.
package ignorefile

import (
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/pflege-de-labs/secobserve-trivyignore/internal/secobserve"
)

var SuppressingStatuses = []string{"False positive", "Not affected", "Not security", "Risk accepted"}

type Entry struct {
	ID        string   `yaml:"id"`
	PURLs     []string `yaml:"purls"`
	ExpiredAt string   `yaml:"expired_at,omitempty"`
	Statement string   `yaml:"statement"`
}

type File struct {
	Vulnerabilities []Entry `yaml:"vulnerabilities"`
}

type Result struct {
	File          File
	SkippedNoPURL int
}

type key struct{ id, purl string }

func Compile(obs []secobserve.Observation, frontendURL string) Result {
	frontendURL = strings.TrimSuffix(frontendURL, "/")
	byKey := map[key]Entry{}
	skipped := 0
	for _, o := range obs {
		// Defence in depth: never suppress on a status the API filter should have excluded.
		if !slices.Contains(SuppressingStatuses, o.CurrentStatus) {
			continue
		}
		if o.VulnerabilityID == "" {
			continue
		}
		if o.OriginComponentPURL == "" {
			skipped++
			continue
		}
		expiry := ""
		if o.CurrentStatus == "Risk accepted" && o.RiskAcceptanceExpiryDate != nil {
			expiry = *o.RiskAcceptanceExpiryDate
		}
		ids := []string{o.VulnerabilityID}
		for _, a := range o.VulnerabilityIDAliases {
			if a.Alias != "" && a.Alias != o.VulnerabilityID {
				ids = append(ids, a.Alias)
			}
		}
		for _, id := range ids {
			k := key{id, o.OriginComponentPURL}
			e := Entry{
				ID:        id,
				PURLs:     []string{o.OriginComponentPURL},
				ExpiredAt: expiry,
				Statement: fmt.Sprintf("%s — %s/#/observations/%d/show", o.CurrentStatus, frontendURL, o.ID),
			}
			if old, ok := byKey[k]; ok && !longerLived(e, old) {
				continue
			}
			byKey[k] = e
		}
	}

	entries := make([]Entry, 0, len(byKey))
	for _, e := range byKey {
		entries = append(entries, e)
	}
	slices.SortFunc(entries, func(a, b Entry) int {
		return strings.Compare(a.ID+"\x00"+a.PURLs[0], b.ID+"\x00"+b.PURLs[0])
	})
	return Result{File: File{Vulnerabilities: entries}, SkippedNoPURL: skipped}
}

// longerLived reports whether a stays valid strictly longer than b; empty expiry means never.
func longerLived(a, b Entry) bool {
	if b.ExpiredAt == "" {
		return false
	}
	return a.ExpiredAt == "" || a.ExpiredAt > b.ExpiredAt
}

func (f File) Marshal() ([]byte, error) {
	if f.Vulnerabilities == nil {
		f.Vulnerabilities = []Entry{}
	}
	return yaml.Marshal(f)
}
