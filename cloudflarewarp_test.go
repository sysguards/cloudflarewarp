package cloudflarewarp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"
	"testing"

	plugin "github.com/sysguards/cloudflarewarp"
)

func TestNew(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.TrustIP = []string{"103.21.244.0/22", "172.18.0.1/32", "2405:b500::/32"}

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	handler, err := plugin.New(ctx, next, cfg, "cloudflarewarp")
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		ipv6           bool
		expect400      bool
		trusted        bool
		remote         string
		desc           string
		cfConnectingIP string
		cfVisitor      string
		expected       string
		expectedScheme string
	}{
		{
			remote:         "103.21.244.23",
			desc:           "blank scheme",
			cfConnectingIP: "10.0.0.1",
			cfVisitor:      "",
			expected:       "10.0.0.1",
			expectedScheme: "",
			trusted:        true,
		},
		{
			remote:         "103.21.244.23",
			desc:           "https scheme",
			cfConnectingIP: "10.0.0.1",
			cfVisitor:      "{\"scheme\":\"https\"}",
			expected:       "10.0.0.1",
			expectedScheme: "https",
			trusted:        true,
		},
		{
			remote:         "10.0.1.20",
			desc:           "not trust",
			cfConnectingIP: "127.0.0.2",
			cfVisitor:      "",
			expected:       "",
			expectedScheme: "",
			trusted:        false,
		},
		{
			remote:         "10.0.1.20",
			desc:           "not trust ip4/6",
			cfConnectingIP: "1001:3984:3989::1",
			cfVisitor:      "",
			expected:       "",
			expectedScheme: "",
			trusted:        false,
		},
		{
			remote:         "1001:3984:3989::1",
			ipv6:           true,
			desc:           "not trust ip6/6",
			cfConnectingIP: "1001:3984:3989::1",
			cfVisitor:      "",
			expected:       "",
			expectedScheme: "",
			trusted:        false,
		},
		{
			remote:         "1001:3984:3989::1",
			ipv6:           true,
			desc:           "not trust ip6/4",
			cfConnectingIP: "10.0.1.20",
			cfVisitor:      "",
			expected:       "",
			expectedScheme: "",
			trusted:        false,
		},
		{
			remote:         "10.0.2",
			desc:           "wrong IP format",
			cfConnectingIP: "10.0.0.1",
			cfVisitor:      "",
			expected:       "",
			expectedScheme: "",
			expect400:      true,
			trusted:        false,
		},
		{
			remote:         "10.0.300.20",
			desc:           "wrong IP address",
			cfConnectingIP: "10.0.0.1",
			cfVisitor:      "",
			expected:       "",
			expectedScheme: "",
			expect400:      true,
			trusted:        false,
		},
		{
			remote:         "103.21.244.23",
			desc:           "forward",
			cfConnectingIP: "10.0.0.1",
			cfVisitor:      "",
			expected:       "10.0.0.1",
			expectedScheme: "",
			trusted:        true,
		},
		{
			remote:         "172.18.0.1",
			desc:           "forward",
			cfConnectingIP: "10.0.0.1",
			cfVisitor:      "",
			expected:       "10.0.0.1",
			expectedScheme: "",
			trusted:        true,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.ipv6 == true {
				req.RemoteAddr = "[" + test.remote + "]:36001"
			} else {
				req.RemoteAddr = test.remote + ":36001"
			}
			req.Header.Set("X-Real-Ip", test.remote)
			req.Header.Set("Cf-Connecting-IP", test.cfConnectingIP)
			req.Header.Set("Cf-Visitor", test.cfVisitor)

			handler.ServeHTTP(recorder, req)

			if recorder.Result().StatusCode == http.StatusBadRequest {
				if test.expect400 == true {
					return
				}
			}
			if recorder.Result().StatusCode != http.StatusOK {
				t.Errorf("invalid response: %d", recorder.Result().StatusCode)
				return
			}

			if test.trusted {
				assertHeader(t, req, "X-Is-Trusted", "yes")
				assertHeader(t, req, "X-Real-Ip", test.expected)
				if expected := test.expected + ":36001"; req.RemoteAddr != expected {
					t.Errorf("invalid RemoteAddr: %s", req.RemoteAddr)
				}
			} else {
				assertHeader(t, req, "X-Is-Trusted", "no")
				assertHeader(t, req, "X-Real-Ip", test.remote)
			}
			assertHeader(t, req, "X-Forwarded-Proto", test.expectedScheme)
		})
	}
}

func TestError(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.TrustIP = []string{"103.21.244.0"}

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	_, err := plugin.New(ctx, next, cfg, "cloudflarewarp")
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestBackendReceivesOnlyTheClientIP(t *testing.T) {
	testCases := []struct {
		desc     string
		remote   string
		clientIP string
	}{
		{desc: "ipv4", remote: "103.21.244.23:36001", clientIP: "10.0.0.1"},
		{desc: "ipv6", remote: "[2400:cb00::1]:36001", clientIP: "2001:db8::1"},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			var received string
			backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				received = req.Header.Get("X-Forwarded-For")
			}))
			t.Cleanup(backend.Close)

			target, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatal(err)
			}

			// Like Traefik, ReverseProxy appends RemoteAddr to X-Forwarded-For.
			proxy := httputil.NewSingleHostReverseProxy(target)
			ctx := context.Background()
			handler, err := plugin.New(ctx, proxy, plugin.CreateConfig(), "cloudflarewarp")
			if err != nil {
				t.Fatal(err)
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = test.remote
			req.Header.Set("Cf-Connecting-IP", test.clientIP)
			req.Header.Set("X-Forwarded-For", "192.0.2.1")

			handler.ServeHTTP(httptest.NewRecorder(), req)

			if received != test.clientIP {
				t.Errorf("invalid X-Forwarded-For: %s", received)
			}
		})
	}
}

func TestMalformedCloudflareHeaders(t *testing.T) {
	const remote = "103.21.244.23:36001"

	testCases := []struct {
		desc           string
		cfConnectingIP string
		cfVisitor      string
	}{
		{desc: "not an ip", cfConnectingIP: "1522.20.2", cfVisitor: "{\"scheme\":\"https\"}"},
		{desc: "two ips", cfConnectingIP: "10.0.0.1, 10.0.0.2", cfVisitor: "{\"scheme\":\"https\"}"},
		{desc: "not a visitor", cfConnectingIP: "10.0.0.1", cfVisitor: "nope"},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	handler, err := plugin.New(ctx, next, plugin.CreateConfig(), "cloudflarewarp")
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = remote
			req.Header.Set("Cf-Connecting-IP", test.cfConnectingIP)
			req.Header.Set("Cf-Visitor", test.cfVisitor)

			handler.ServeHTTP(httptest.NewRecorder(), req)

			assertHeader(t, req, "X-Is-Trusted", "danger")
			assertHeader(t, req, "Cf-Connecting-IP", "")
			assertHeader(t, req, "Cf-Visitor", "")
			if req.RemoteAddr != remote {
				t.Errorf("invalid RemoteAddr: %s", req.RemoteAddr)
			}
		})
	}
}

func TestAutoUpdateIPs(t *testing.T) {
	testCases := []struct {
		desc           string
		disableDefault bool
		expected       string
	}{
		{desc: "embedded list applies right away, whether the download works or not", expected: "yes"},
		{desc: "disableDefault wins", disableDefault: true, expected: "no"},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			cfg := plugin.CreateConfig()
			cfg.AutoUpdateIPs = true
			cfg.DisableDefault = test.disableDefault

			ctx := context.Background()
			next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
			handler, err := plugin.New(ctx, next, cfg, "cloudflarewarp")
			if err != nil {
				t.Fatal(err)
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = "103.21.244.23:36001"
			req.Header.Set("Cf-Connecting-IP", "10.0.0.1")

			handler.ServeHTTP(httptest.NewRecorder(), req)

			assertHeader(t, req, "X-Is-Trusted", test.expected)
		})
	}
}

func TestConfigKeysMatchFieldNames(t *testing.T) {
	configType := reflect.TypeOf(*plugin.CreateConfig())

	for _, key := range []string{"trustip", "disableDefault", "autoUpdateIPs"} {
		_, found := configType.FieldByNameFunc(func(name string) bool {
			return strings.EqualFold(name, key)
		})
		if !found {
			t.Errorf("no Config field matches the configuration key %s, Traefik would ignore it", key)
		}
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header(%s) value: %s", key, req.Header.Get(key))
	}
}
