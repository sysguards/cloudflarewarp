package ips_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sysguards/cloudflarewarp/ips"
)

const (
	validBody = `{"success":true,"result":{"ipv4_cidrs":["198.51.100.0/24"],"ipv6_cidrs":["2001:db8::/32"]}}`
	initialIP = "203.0.113.1"
	updatedIP = "198.51.100.1"
)

func newStore(t *testing.T) *ips.Store {
	t.Helper()

	store, err := ips.NewStore([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}

	return store
}

func serve(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(status)
		_, _ = rw.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return server
}

func assertKeptInitialList(t *testing.T, store *ips.Store) {
	t.Helper()

	if !store.Contains(net.ParseIP(initialIP)) {
		t.Error("the initial list was lost")
	}
	if store.Contains(net.ParseIP(updatedIP)) {
		t.Error("the rejected list was applied")
	}
}

func TestNewStoreRejectsInvalidCIDR(t *testing.T) {
	if _, err := ips.NewStore([]string{"203.0.113.0"}); err == nil {
		t.Fatal("expected error, got none")
	}
}

func TestCFIPsIsValid(t *testing.T) {
	store, err := ips.NewStore(ips.CFIPs())
	if err != nil {
		t.Fatal(err)
	}
	if !store.Contains(net.ParseIP("103.21.244.23")) || !store.Contains(net.ParseIP("2400:cb00::1")) {
		t.Error("the embedded list does not cover the Cloudflare ranges")
	}
}

func TestRefreshReplacesList(t *testing.T) {
	store := newStore(t)
	server := serve(t, http.StatusOK, validBody)

	if err := store.Refresh(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}

	if store.Contains(net.ParseIP(initialIP)) {
		t.Error("the initial list is still applied")
	}
	if !store.Contains(net.ParseIP(updatedIP)) || !store.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("the downloaded list was not applied")
	}
}

func TestRefreshRejectsBadResponses(t *testing.T) {
	testCases := []struct {
		desc   string
		status int
		body   string
	}{
		{desc: "server error", status: http.StatusInternalServerError, body: validBody},
		{desc: "not json", status: http.StatusOK, body: "<html>"},
		{desc: "api failure", status: http.StatusOK, body: strings.Replace(validBody, "true", "false", 1)},
		{desc: "no ipv4", status: http.StatusOK, body: `{"success":true,"result":{"ipv4_cidrs":[],"ipv6_cidrs":["2001:db8::/32"]}}`},
		{desc: "no ipv6", status: http.StatusOK, body: `{"success":true,"result":{"ipv4_cidrs":["198.51.100.0/24"],"ipv6_cidrs":[]}}`},
		{desc: "invalid range", status: http.StatusOK, body: `{"success":true,"result":{"ipv4_cidrs":["198.51.100.0/24","nope"],"ipv6_cidrs":["2001:db8::/32"]}}`},
		{desc: "ipv6 in the ipv4 list", status: http.StatusOK, body: `{"success":true,"result":{"ipv4_cidrs":["2001:db8::/32"],"ipv6_cidrs":["2001:db8::/32"]}}`},
		{desc: "ipv4 in the ipv6 list", status: http.StatusOK, body: `{"success":true,"result":{"ipv4_cidrs":["198.51.100.0/24"],"ipv6_cidrs":["198.51.100.0/24"]}}`},
		{desc: "ipv4-mapped range", status: http.StatusOK, body: `{"success":true,"result":{"ipv4_cidrs":["198.51.100.0/24"],"ipv6_cidrs":["::ffff:0:0/96"]}}`},
		{desc: "every ipv4 address", status: http.StatusOK, body: `{"success":true,"result":{"ipv4_cidrs":["0.0.0.0/0"],"ipv6_cidrs":["2001:db8::/32"]}}`},
		{desc: "every ipv6 address", status: http.StatusOK, body: `{"success":true,"result":{"ipv4_cidrs":["198.51.100.0/24"],"ipv6_cidrs":["::/0"]}}`},
		{desc: "oversized body", status: http.StatusOK, body: `{"padding":"` + strings.Repeat("x", 2<<20) + `",` + validBody[1:]},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			store := newStore(t)
			server := serve(t, test.status, test.body)

			if err := store.Refresh(context.Background(), server.URL); err == nil {
				t.Error("expected error, got none")
			}

			assertKeptInitialList(t, store)
		})
	}
}

func TestRefreshRefusesRedirects(t *testing.T) {
	target := serve(t, http.StatusOK, validBody)
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, target.URL, http.StatusFound)
	}))
	t.Cleanup(server.Close)

	store := newStore(t)
	if err := store.Refresh(context.Background(), server.URL); err == nil {
		t.Error("expected error, got none")
	}

	assertKeptInitialList(t, store)
}

func TestRefreshKeepsListWhenUnreachable(t *testing.T) {
	server := serve(t, http.StatusOK, validBody)
	server.Close()

	store := newStore(t)
	if err := store.Refresh(context.Background(), server.URL); err == nil {
		t.Error("expected error, got none")
	}

	assertKeptInitialList(t, store)
}

func TestRunRetriesAfterFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = rw.Write([]byte(validBody))
	}))
	t.Cleanup(server.Close)

	store := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		store.Run(ctx, server.URL, time.Hour, 10*time.Millisecond)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for !store.Contains(net.ParseIP(updatedIP)) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	<-done

	if !store.Contains(net.ParseIP(updatedIP)) {
		t.Error("the list was not updated after the failed attempt")
	}
}

func TestRunSurvivesPanic(_ *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Without an HTTP client, the refresh panics.
	var store ips.Store
	store.Run(ctx, "http://localhost", time.Hour, time.Hour)
}

func TestContainsDuringRefresh(t *testing.T) {
	store := newStore(t)
	server := serve(t, http.StatusOK, validBody)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ { //nolint:intrange,modernize // Yaegi cannot range over an integer.
			store.Contains(net.ParseIP(updatedIP))
		}
	}()

	for i := 0; i < 10; i++ { //nolint:intrange,modernize // Yaegi cannot range over an integer.
		if err := store.Refresh(context.Background(), server.URL); err != nil {
			t.Error(err)
		}
	}

	<-done
}
