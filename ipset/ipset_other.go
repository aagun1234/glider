//go:build !linux

package ipset

import (
	"errors"
	"net/netip"

	"github.com/aagun1234/glider/rule"
)

// Manager struct
type Manager struct{}

// NewManager returns a Manager
func NewManager(rules []*rule.Config) (*Manager, error) {
	return nil, errors.New("ipset not supported on this os")
}

// AddDomainIP implements the DNSAnswerHandler function
func (m *Manager) AddDomainIP(domain string, ip netip.Addr) error {
	return errors.New("ipset not supported on this os")
}
