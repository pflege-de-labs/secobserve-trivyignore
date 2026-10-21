package secobserve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestListProductsSendsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "APIToken t0k" {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path != "/api/products/" || r.URL.Query().Get("page_size") != "500" {
			t.Errorf("unexpected URL %s", r.URL)
		}
		_, _ = w.Write([]byte(`{"count":1,"next":null,"previous":null,"results":[{"id":1,"name":"p","repository_prefix":"org/repo","repository_default_branch":3}]}`))
	}))
	defer srv.Close()

	// trailing slash must be tolerated
	got, err := New(srv.URL+"/", "t0k", nil).ListProducts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b := 3
	want := []Product{{ID: 1, Name: "p", RepositoryPrefix: "org/repo", RepositoryDefaultBranch: &b}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestListObservationsQuery(t *testing.T) {
	statuses := []string{"Not affected", "Not security", "False positive", "Risk accepted"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !reflect.DeepEqual(q["current_status"], statuses) {
			t.Errorf("current_status = %v", q["current_status"])
		}
		if q.Get("product") != "7" || q.Get("branch") != "3" || q.Get("page_size") != "500" {
			t.Errorf("query = %v", q)
		}
		_, _ = w.Write([]byte(`{"next":null,"results":[]}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "t", nil).ListObservations(context.Background(), 7, 3, statuses); err != nil {
		t.Fatal(err)
	}
}

func TestListObservationsFollowsPages(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`{"next":null,"results":[{"id":3}]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"next":    srv.URL + "/api/observations/?page=2",
			"results": []Observation{{ID: 1}, {ID: 2}},
		})
	}))
	defer srv.Close()

	got, err := New(srv.URL, "t", nil).ListObservations(context.Background(), 1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2].ID != 3 {
		t.Errorf("got %+v", got)
	}
}

func TestListProductsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret body", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "t0k", nil).ListProducts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "secret body") || strings.Contains(err.Error(), "t0k") {
		t.Errorf("err = %v", err)
	}
}

func TestListFollowsNextQueryOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`{"next":null,"results":[{"id":3}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"next":"http://evil.example/other/?page=2&page_size=500","results":[{"id":1},{"id":2}]}`))
	}))
	defer srv.Close()

	got, err := New(srv.URL, "t", nil).ListObservations(context.Background(), 1, 1, nil)
	if err != nil || len(got) != 3 {
		t.Fatalf("got %+v, err %v", got, err)
	}
}
