package ips

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	apiURL          = "https://api.cloudflare.com/client/v4/ips"
	requestTimeout  = 5 * time.Second
	refreshInterval = 24 * time.Hour
	retryInterval   = time.Hour
	maxResponseSize = 1 << 20
	minIPv4Prefix   = 8
	minIPv6Prefix   = 16
)

// Traefik calls New for every router and on every reload: they must all share one list and one refresh loop.
//
//nolint:gochecknoglobals
var (
	shared     *Store
	errShared  error
	sharedOnce sync.Once
)

//nolint:tagliatelle // Field names of the Cloudflare API.
type apiResult struct {
	IPv4CIDRs []string `json:"ipv4_cidrs"`
	IPv6CIDRs []string `json:"ipv6_cidrs"`
}

type apiResponse struct {
	Success bool      `json:"success"`
	Result  apiResult `json:"result"`
}

// Store is a list of networks that can be replaced while it is being read.
type Store struct {
	mu       sync.RWMutex
	networks []*net.IPNet
	client   *http.Client
}

// Shared returns the list seeded from CFIPs, starting its background refresh on the first call.
func Shared() (*Store, error) {
	sharedOnce.Do(func() {
		shared, errShared = NewStore(CFIPs())
		if errShared == nil {
			// The context given to New belongs to a single router build: canceling it must not stop the refresh for the others.
			go shared.Run(context.Background(), apiURL, refreshInterval, retryInterval)
		}
	})

	return shared, errShared
}

// NewStore creates a Store holding the given CIDR ranges.
func NewStore(cidrs []string) (*Store, error) {
	networks, err := parseCIDRs(cidrs)
	if err != nil {
		return nil, err
	}

	return &Store{
		networks: networks,
		client: &http.Client{
			Timeout: requestTimeout,
			// A redirect could leave HTTPS, and this list decides who may set CF-Connecting-IP.
			// The parameters must stay named: Yaegi panics on this callback otherwise.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Contains reports whether ip belongs to one of the networks.
func (s *Store) Contains(ip net.IP) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, network := range s.networks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// Refresh replaces the list with the one served at url, or leaves it untouched on any error.
func (s *Store) Refresh(ctx context.Context, url string) error {
	networks, err := s.fetch(ctx, url)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.networks = networks

	return nil
}

// Run refreshes the list until ctx is canceled, waiting retryEvery instead of refreshEvery after a failure.
func (s *Store) Run(ctx context.Context, url string, refreshEvery, retryEvery time.Duration) {
	for {
		delay := refreshEvery

		// Traefik sends the log package to its error level and fmt to its debug level.
		if err := s.safeRefresh(ctx, url); err != nil {
			delay = retryEvery
			log.Printf("cloudflarewarp: IP list update failed, keeping the current list: %v", err)
		} else {
			fmt.Println("cloudflarewarp: IP list updated")
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// safeRefresh turns a panic into an error: Run has its own goroutine, where a panic would stop Traefik.
func (s *Store) safeRefresh(ctx context.Context, url string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
		}
	}()

	return s.Refresh(ctx, url)
}

func (s *Store) fetch(ctx context.Context, url string) ([]*net.IPNet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return parseResponse(io.LimitReader(resp.Body, maxResponseSize))
}

func parseResponse(body io.Reader) ([]*net.IPNet, error) {
	var response apiResponse
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		return nil, err
	}

	if !response.Success {
		return nil, errors.New("the API reported a failure")
	}

	ipv4, err := parseFamily(response.Result.IPv4CIDRs, net.IPv4len, minIPv4Prefix)
	if err != nil {
		return nil, err
	}

	ipv6, err := parseFamily(response.Result.IPv6CIDRs, net.IPv6len, minIPv6Prefix)
	if err != nil {
		return nil, err
	}

	return append(ipv4, ipv6...), nil
}

func parseFamily(cidrs []string, maskLen, minPrefix int) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, errors.New("empty range list")
	}

	networks, err := parseCIDRs(cidrs)
	if err != nil {
		return nil, err
	}

	for _, network := range networks {
		if err := validateNetwork(network, maskLen, minPrefix); err != nil {
			return nil, err
		}
	}

	return networks, nil
}

func validateNetwork(network *net.IPNet, maskLen, minPrefix int) error {
	// An IPv4-mapped range such as ::ffff:0:0/96 passes as IPv6 but matches every IPv4 address.
	isIPv4Mapped := len(network.Mask) == net.IPv6len && network.IP.To4() != nil
	if len(network.Mask) != maskLen || isIPv4Mapped {
		return fmt.Errorf("range %s has the wrong address family", network)
	}

	if prefix, _ := network.Mask.Size(); prefix < minPrefix {
		return fmt.Errorf("range %s is too broad", network)
	}

	return nil
}

func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(cidrs))

	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}

		networks = append(networks, network)
	}

	return networks, nil
}
