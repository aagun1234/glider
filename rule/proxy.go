package rule

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/proxy"
)

// Proxy implements the proxy.Proxy interface with rule support.
type Proxy struct {
	main      *FwdrGroup
	all       []*FwdrGroup
	domainMap sync.Map
	ipMap     sync.Map
	cidrMap   sync.Map
}

// NewProxy returns a new rule proxy.
func NewProxy(mainForwarders []string, mainStrategy *Strategy, rules []*Config) *Proxy {
	rd := &Proxy{main: NewFwdrGroup("main", mainForwarders, mainStrategy)}

	for _, r := range rules {
		group := NewFwdrGroup(r.RulePath, r.Forward, &r.Strategy)
		rd.all = append(rd.all, group)

		for _, domain := range r.Domain {
			rd.domainMap.Store(strings.ToLower(domain), group)
		}

		for _, s := range r.IP {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				log.F("[rule] parse ip error: %s", err)
				continue
			}
			rd.ipMap.Store(ip, group)
		}

		for _, s := range r.CIDR {
			cidr, err := netip.ParsePrefix(s)
			if err != nil {
				log.F("[rule] parse cidr error: %s", err)
				continue
			}
			rd.cidrMap.Store(cidr, group)
		}
	}

	direct := NewFwdrGroup("", nil, mainStrategy)
	rd.domainMap.Store("direct", direct)

	// if there's any forwarder defined in main config, make sure they will be accessed directly.
	if len(mainForwarders) > 0 {
		for _, f := range rd.main.fwdrs {
			addr := strings.Split(f.addr, ",")[0]
			host, _, _ := net.SplitHostPort(addr)
			if _, err := netip.ParseAddr(host); err != nil {
				rd.domainMap.Store(strings.ToLower(host), direct)
			}
		}
	}

	return rd
}

// Dial dials to targer addr and return a conn.
func (p *Proxy) Dial(network, addr string) (net.Conn, proxy.Dialer, error) {
	return p.findDialer(addr).Dial(network, addr)
}

// DialUDP connects to the given address via the proxy.
func (p *Proxy) DialUDP(network, addr string) (pc net.PacketConn, dialer proxy.UDPDialer, err error) {
	return p.findDialer(addr).DialUDP(network, addr)
}

// findDialer returns a dialer by dstAddr according to rule.
func (p *Proxy) findDialer(dstAddr string) *FwdrGroup {
	host, _, err := net.SplitHostPort(dstAddr)
	if err != nil {
		return p.main
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		// check ip
		if proxy, ok := p.ipMap.Load(ip); ok {
			return proxy.(*FwdrGroup)
		}

		// check cidr
		var ret *FwdrGroup
		p.cidrMap.Range(func(key, value any) bool {
			if key.(netip.Prefix).Contains(ip) {
				ret = value.(*FwdrGroup)
				return false
			}
			return true
		})

		if ret != nil {
			return ret
		}
	}

	// check host
	host = strings.ToLower(host)
	for i := len(host); i != -1; {
		i = strings.LastIndexByte(host[:i], '.')
		if proxy, ok := p.domainMap.Load(host[i+1:]); ok {
			return proxy.(*FwdrGroup)
		}
	}

	return p.main
}

// NextDialer returns next dialer according to rule.
func (p *Proxy) NextDialer(dstAddr string) proxy.Dialer {
	return p.findDialer(dstAddr).NextDialer(dstAddr)
}

// Record records result while using the dialer from proxy.
func (p *Proxy) Record(dialer proxy.Dialer, success bool) {
	if fwdr, ok := dialer.(*Forwarder); ok {
		if !success {
			fwdr.IncFailures()
			return
		}
		fwdr.Enable()
	}
}

// AddDomainIP used to update ipMap rules according to domainMap rule.
func (p *Proxy) AddDomainIP(domain string, ip netip.Addr) error {
	domain = strings.ToLower(domain)
	for i := len(domain); i != -1; {
		i = strings.LastIndexByte(domain[:i], '.')
		if dialer, ok := p.domainMap.Load(domain[i+1:]); ok {
			p.ipMap.Store(ip, dialer)
			// log.F("[rule] update map: %s/%s based on rule: domain=%s\n", domain, ip, domain[i+1:])
		}
	}
	return nil
}

// Check checks availability of forwarders inside proxy.
func (p *Proxy) Check() {
	p.main.Check()

	for _, fwdrGroup := range p.all {
		fwdrGroup.Check()
	}
}

type ProxyStatus struct {
	ID		uint32 `json:"id"`
	URL         string `json:"url"`
	Priority    uint32 `json:"priority"`
	MaxFailures 	uint32 `json:"max_failures"` // maxfailures to set to Disabled
	Enabled    bool `json:"enabled"`
	ChkCount	uint32 `json:"chkcount"`
	MDisabled    bool `json:"manualy_disabled"`
	TotalFails    uint32 `json:"failures"`
	Latency     int64  `json:"latency"`
	InBytes		uint64 `json:"inbytes"`
	OutBytes		uint64 `json:"outbytes"`
}


func (p *Proxy) GetMainStatus(index uint32,url,enabled string) []ProxyStatus {
	pstatus:=[]ProxyStatus{}
	aa:=make(map[uint32]bool)
	bb:=false
	if enabled=="1" {
		bb=true
	}

		for i := 0; i < len(p.main.fwdrs); i++ {
			status:=ProxyStatus{
				ID:		p.main.fwdrs[i].FID(),
				URL:         p.main.fwdrs[i].url,
				Priority:    p.main.fwdrs[i].Priority(),
				MaxFailures: p.main.fwdrs[i].MaxFailures(),
				Enabled:    p.main.fwdrs[i].Enabled(),
				ChkCount:	p.main.fwdrs[i].ChkCount(),
				MDisabled:    p.main.fwdrs[i].MDisabled(),
				TotalFails:    p.main.fwdrs[i].TotalFails(),
				Latency:     p.main.fwdrs[i].Latency()/int64(time.Millisecond),
			}
			if (index==0 || index==p.main.fwdrs[i].FID()) && (url =="" || strings.Contains(p.main.fwdrs[i].URL(), url)) && (enabled =="" || bb==p.main.fwdrs[i].Enabled()) {
				if _, ok := aa[p.main.fwdrs[i].FID()]; !ok {
					pstatus=append(pstatus, status)
					aa[p.main.fwdrs[i].FID()]=true
				}
			}

		}

	for _,fg := range p.all {	
		for i := 0; i < len(fg.fwdrs); i++ {
			status:=ProxyStatus{
				ID:		fg.fwdrs[i].FID(),
				URL:         fg.fwdrs[i].url,
				Priority:    fg.fwdrs[i].Priority(),
				MaxFailures: fg.fwdrs[i].MaxFailures(),
				Enabled:    fg.fwdrs[i].Enabled(),
				MDisabled:    fg.fwdrs[i].MDisabled(),
				TotalFails:    fg.fwdrs[i].TotalFails(),
				ChkCount:	fg.fwdrs[i].ChkCount(),
				Latency:     fg.fwdrs[i].Latency()/int64(time.Millisecond),
			}
			if (index==0 || index==fg.fwdrs[i].FID()) && (url =="" || strings.Contains(fg.fwdrs[i].URL(), url)) && (enabled =="" || bb==fg.fwdrs[i].Enabled()) {
				if _, ok := aa[fg.fwdrs[i].FID()]; !ok {
					pstatus=append(pstatus, status)
					aa[fg.fwdrs[i].FID()]=true
				}
			}

		}
	}

	return pstatus
}

func (p *Proxy) GetMainEnabled(stat bool) []ProxyStatus {
	pstatus:=[]ProxyStatus{}
	aa:=make(map[uint32]bool)

		for i := 0; i < len(p.main.fwdrs); i++ {
			status:=ProxyStatus{
				ID:		p.main.fwdrs[i].FID(),
				URL:         p.main.fwdrs[i].url,
				Priority:    p.main.fwdrs[i].Priority(),
				MaxFailures: p.main.fwdrs[i].MaxFailures(),
				Enabled:    p.main.fwdrs[i].Enabled(),
				MDisabled:    p.main.fwdrs[i].MDisabled(),
				ChkCount:	p.main.fwdrs[i].ChkCount(),
				TotalFails:    p.main.fwdrs[i].TotalFails(),
				Latency:     p.main.fwdrs[i].Latency()/int64(time.Millisecond),
			}
			if p.main.fwdrs[i].Enabled() == stat {
				if _, ok := aa[p.main.fwdrs[i].FID()]; !ok {
					pstatus=append(pstatus, status)
					aa[p.main.fwdrs[i].FID()]=true
				}
			}

		}
	for _,fg := range p.all {	
		for i := 0; i < len(fg.fwdrs); i++ {
			status:=ProxyStatus{
				ID:		fg.fwdrs[i].FID(),
				URL:         fg.fwdrs[i].url,
				Priority:    fg.fwdrs[i].Priority(),
				MaxFailures: fg.fwdrs[i].MaxFailures(),
				Enabled:    fg.fwdrs[i].Enabled(),
				ChkCount:	fg.fwdrs[i].ChkCount(),
				MDisabled:    fg.fwdrs[i].MDisabled(),
				TotalFails:    fg.fwdrs[i].TotalFails(),
				Latency:     fg.fwdrs[i].Latency()/int64(time.Millisecond),
			}
			if fg.fwdrs[i].Enabled() == stat {
				if _, ok := aa[fg.fwdrs[i].FID()]; !ok {
					pstatus=append(pstatus, status)
					aa[fg.fwdrs[i].FID()]=true
				}
			}

		}
	}
	return pstatus
}


func (p *Proxy) OperateMain(id uint32, url, enabled, stat string) []ProxyStatus{
	pstatus:=[]ProxyStatus{}
	aa:=make(map[uint32]bool)
	bb:=false
	if enabled=="1" {
		bb=true
	}
	
	for i := 0; i < len(p.main.fwdrs); i++ {
		status:=ProxyStatus{
				ID:		p.main.fwdrs[i].FID(),
				URL:         p.main.fwdrs[i].url,
				Priority:    p.main.fwdrs[i].Priority(),
				MaxFailures: p.main.fwdrs[i].MaxFailures(),
				Enabled:    p.main.fwdrs[i].Enabled(),
				ChkCount:	p.main.fwdrs[i].ChkCount(),
				MDisabled:    p.main.fwdrs[i].MDisabled(),
				TotalFails:    p.main.fwdrs[i].TotalFails(),
				Latency:     p.main.fwdrs[i].Latency()/int64(time.Millisecond),
		}
		if (id==0 || id==p.main.fwdrs[i].FID()) && (url =="" || strings.Contains(p.main.fwdrs[i].URL(), url)) && (enabled =="" || bb==p.main.fwdrs[i].Enabled()) {
			switch stat {
				case "enable":
					p.main.fwdrs[i].MEnable()
					status.MDisabled=false
					status.Enabled=true
				case "disable":
					p.main.fwdrs[i].MDisable()
					status.MDisabled=true
					status.Enabled=false
				default:
			}
			if _, ok := aa[p.main.fwdrs[i].FID()]; !ok {
				pstatus=append(pstatus, status)
				aa[p.main.fwdrs[i].FID()]=true
			}
			
		}

	}
	for _,fg := range p.all {	
		for i := 0; i < len(fg.fwdrs); i++ {
			status:=ProxyStatus{
				ID:		fg.fwdrs[i].FID(),
				URL:         fg.fwdrs[i].url,
				Priority:    fg.fwdrs[i].Priority(),
				MaxFailures: fg.fwdrs[i].MaxFailures(),
				Enabled:    fg.fwdrs[i].Enabled(),
				ChkCount:	fg.fwdrs[i].ChkCount(),
				MDisabled:    fg.fwdrs[i].MDisabled(),
				TotalFails:    fg.fwdrs[i].TotalFails(),
				Latency:     fg.fwdrs[i].Latency()/int64(time.Millisecond),
			}
			if (id==0 || id==fg.fwdrs[i].FID()) && (url =="" || strings.Contains(fg.fwdrs[i].URL(), url)) && (enabled =="" || bb==fg.fwdrs[i].Enabled()) {
				switch stat {
					case "enable":
						fg.fwdrs[i].MEnable()
						status.MDisabled=false
						status.Enabled=true
					case "disable":
						fg.fwdrs[i].MDisable()
						status.MDisabled=true
						status.Enabled=false
					default:
				}
				if _, ok := aa[fg.fwdrs[i].FID()]; !ok {
					pstatus=append(pstatus, status)
					aa[fg.fwdrs[i].FID()]=true
				}
			}

		}
	}

	return pstatus
}



func (p *Proxy) SetCheckNow(id uint32, url, enabled string) {
	bb:=false
	if enabled=="1" {
		bb=true
	}

	for i := 0; i < len(p.main.fwdrs); i++ {
		if (id==0 || id==p.main.fwdrs[i].FID()) && (url =="" || strings.Contains(p.main.fwdrs[i].URL(), url)) && (enabled =="" || bb==p.main.fwdrs[i].Enabled()) {
			p.main.fwdrs[i].SetCheckNow()
			
		}

	}
	for _,fg := range p.all {	
		for i := 0; i < len(fg.fwdrs); i++ {
			if (id==0 || id==fg.fwdrs[i].FID()) && (url =="" || strings.Contains(fg.fwdrs[i].URL(), url)) && (enabled =="" || bb==fg.fwdrs[i].Enabled()) {
				fg.fwdrs[i].SetCheckNow()
				
			}

		}
	}

	return 
}