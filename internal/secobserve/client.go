// Package secobserve is a minimal read-only client for the SecObserve REST API.
package secobserve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Product struct {
	ID                      int    `json:"id"`
	Name                    string `json:"name"`
	RepositoryPrefix        string `json:"repository_prefix"`
	RepositoryDefaultBranch *int   `json:"repository_default_branch"`
}

type Alias struct {
	Alias string `json:"alias"`
}

type Observation struct {
	ID                       int     `json:"id"`
	CurrentStatus            string  `json:"current_status"`
	VulnerabilityID          string  `json:"vulnerability_id"`
	VulnerabilityIDAliases   []Alias `json:"vulnerability_id_aliases"`
	OriginComponentPURL      string  `json:"origin_component_purl"`
	RiskAcceptanceExpiryDate *string `json:"risk_acceptance_expiry_date"` // "YYYY-MM-DD"
}

type Client struct {
	baseURL string
	token   string
	hc      *http.Client
}

func New(baseURL, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, hc: hc}
}

func (c *Client) ListProducts(ctx context.Context) ([]Product, error) {
	return list[Product](ctx, c, c.baseURL+"/api/products/", "page_size=500")
}

func (c *Client) ListObservations(ctx context.Context, productID, branchID int, statuses []string) ([]Observation, error) {
	q := url.Values{}
	q.Set("product", strconv.Itoa(productID))
	q.Set("branch", strconv.Itoa(branchID))
	for _, s := range statuses {
		q.Add("current_status", s)
	}
	q.Set("page_size", "500")
	return list[Observation](ctx, c, c.baseURL+"/api/observations/", q.Encode())
}

// list follows only next's query string so the token never goes to a host the server names.
func list[T any](ctx context.Context, c *Client, endpoint, query string) ([]T, error) {
	var all []T
	for {
		var page struct {
			Next    *string `json:"next"`
			Results []T     `json:"results"`
		}
		if err := c.get(ctx, endpoint+"?"+query, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Results...)
		if page.Next == nil || *page.Next == "" {
			return all, nil
		}
		nu, err := url.Parse(*page.Next)
		if err != nil {
			return nil, fmt.Errorf("secobserve: parse next link: %w", err)
		}
		query = nu.RawQuery
	}
}

func (c *Client) get(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("secobserve: build request: %w", err)
	}
	req.Header.Set("Authorization", "APIToken "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		// url.Error carries the URL only, never headers, so the token stays out.
		return fmt.Errorf("secobserve: GET %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("secobserve: GET %s: status %d", req.URL.Path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("secobserve: GET %s: decode: %w", req.URL.Path, err)
	}
	return nil
}
