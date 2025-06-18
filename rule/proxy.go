package rule

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
	"strconv"
	"fmt"

	"github.com/aagun1234/glider/pkg/log"
	"github.com/aagun1234/glider/proxy"
)

// Proxy implements the proxy.Proxy interface with rule support.
type Proxy struct {
	main      *FwdrGroup
	all       []*FwdrGroup
	domainMap sync.Map
	ipMap     sync.Map
	cidrMap   sync.Map
	ratelimit int64
}

// NewProxy returns a new rule proxy.
func NewProxy(mainForwarders []string, mainStrategy *Strategy, rules []*Config) *Proxy {
	rd := &Proxy{main: NewFwdrGroup("main", mainForwarders, mainStrategy)}
	rd.SetRateLimit(0)
	
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

// Record records result while using the dialer from proxy.
func (p *Proxy) UpdateInOut(dialer proxy.Dialer, inbytes,outbytes uint64) {
	if fwdr, ok := dialer.(*Forwarder); ok {
		fwdr.AddInBytes(inbytes)
		fwdr.AddOutBytes(outbytes)
	}
}

// Record records result while using the dialer from proxy.
func (p *Proxy) SetRateLimit(rate int64) {
	p.ratelimit=rate
}

// Record records result while using the dialer from proxy.
func (p *Proxy) GetRateLimit() (int64){
	return(p.ratelimit)
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
	Maps	string `json:"routemap"`
	GroupName    string `json:"groupname"`
	GroupStrategy    string `json:"groupstrategy"`
}

func syncMapToString(m *sync.Map, target interface{}) []interface{} {
	var keys []interface{}

	// 使用 Range 方法遍历 sync.Map
	m.Range(func(key, value interface{}) bool {
		if value == target {
			keys = append(keys, key) // 将符合条件的键添加到切片中
		}
		return true // 继续遍历
	})

	return keys
}

func (p *Proxy) MatchRoutes(target interface{}) string {

	mapstr:=""
	mapstr1:=fmt.Sprintf("%v",syncMapToString(&p.cidrMap,target))
	if mapstr1!="[]" {
		mapstr=mapstr+mapstr1+";"
	}
	mapstr1=fmt.Sprintf("%v",syncMapToString(&p.ipMap,target))
	if mapstr1!="[]" {
		mapstr=mapstr+mapstr1+";"
	}
	mapstr1=fmt.Sprintf("%v",syncMapToString(&p.domainMap,target))
	if mapstr1!="[]" {
		mapstr=mapstr+mapstr1
	}
	return mapstr
}

func (p *Proxy) GetMainStatus(index uint32, url,enabled string,prio int) []ProxyStatus {
	pstatus:=[]ProxyStatus{}
	aa:=make(map[uint32]bool)
	bb:=false
	if enabled!="0" || enabled=="true" {
		bb=true
	}
	
		for i := 0; i < len(p.main.fwdrs); i++ {
			mapstr:=p.MatchRoutes(p.main)
			if mapstr=="" {
				mapstr="[0/0]"
			}
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
				InBytes:	p.main.fwdrs[i].InBytes(),
				OutBytes:	p.main.fwdrs[i].OutBytes(),
				Maps:	mapstr,
				GroupName:	p.main.name,
				GroupStrategy:	p.main.config.Strategy,
			}
			if (index==0 || index==p.main.fwdrs[i].FID()) && (url =="" || strings.Contains(p.main.fwdrs[i].URL(), url)) && (enabled =="" || bb==p.main.fwdrs[i].Enabled()) && (prio==-1 || uint32(prio)==p.main.fwdrs[i].Priority()) {
				if _, ok := aa[p.main.fwdrs[i].FID()]; !ok {
					pstatus=append(pstatus, status)
					aa[p.main.fwdrs[i].FID()]=true
				}
			}

		}

	for _,fg := range p.all {	
		for i := 0; i < len(fg.fwdrs); i++ {
			mapstr:=p.MatchRoutes(fg)
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
				InBytes:	fg.fwdrs[i].InBytes(),
				OutBytes:	fg.fwdrs[i].OutBytes(),
				Maps:	mapstr,
				GroupName:	fg.name,
				GroupStrategy:	fg.config.Strategy,				
			}
			if (index==0 || index==fg.fwdrs[i].FID()) && (url =="" || strings.Contains(fg.fwdrs[i].URL(), url)) && (enabled =="" || bb==fg.fwdrs[i].Enabled()) && (prio==-1 || uint32(prio)==fg.fwdrs[i].Priority()) {
				if _, ok := aa[fg.fwdrs[i].FID()]; !ok {
					pstatus=append(pstatus, status)
					aa[fg.fwdrs[i].FID()]=true
				}
			}

		}
	}

	return pstatus
}




func (p *Proxy) GetAvailStatus(index uint32,url,enabled string,prio int) []ProxyStatus {
	pstatus:=[]ProxyStatus{}
	aa:=make(map[uint32]bool)
	bb:=false
	if enabled!="0" || enabled=="true" {
		bb=true
	}
	
		for i := 0; i < len(p.main.avail); i++ {
			mapstr:=p.MatchRoutes(p.main)
			if mapstr=="" {
				mapstr="[0/0]"
			}
			status:=ProxyStatus{
				ID:		p.main.avail[i].FID(),
				URL:         p.main.avail[i].url,
				Priority:    p.main.avail[i].Priority(),
				MaxFailures: p.main.avail[i].MaxFailures(),
				Enabled:    p.main.avail[i].Enabled(),
				ChkCount:	p.main.avail[i].ChkCount(),
				MDisabled:    p.main.avail[i].MDisabled(),
				TotalFails:    p.main.avail[i].TotalFails(),
				Latency:     p.main.avail[i].Latency()/int64(time.Millisecond),
				InBytes:	p.main.avail[i].InBytes(),
				OutBytes:	p.main.avail[i].OutBytes(),
				Maps:	mapstr,
				GroupName:	p.main.name,
				GroupStrategy:	p.main.config.Strategy,
			}
			if (index==0 || index==p.main.avail[i].FID()) && (url =="" || strings.Contains(p.main.avail[i].URL(), url)) && (enabled =="" || bb==p.main.avail[i].Enabled()) && (prio==-1 || uint32(prio)==p.main.avail[i].Priority()) {
				if _, ok := aa[p.main.avail[i].FID()]; !ok {
					pstatus=append(pstatus, status)
					aa[p.main.avail[i].FID()]=true
				}
			}

		}

	for _,fg := range p.all {	
		for i := 0; i < len(fg.avail); i++ {
			mapstr:=p.MatchRoutes(fg)
			status:=ProxyStatus{
				ID:		fg.avail[i].FID(),
				URL:         fg.avail[i].url,
				Priority:    fg.avail[i].Priority(),
				MaxFailures: fg.avail[i].MaxFailures(),
				Enabled:    fg.avail[i].Enabled(),
				MDisabled:    fg.avail[i].MDisabled(),
				TotalFails:    fg.avail[i].TotalFails(),
				ChkCount:	fg.avail[i].ChkCount(),
				Latency:     fg.avail[i].Latency()/int64(time.Millisecond),
				InBytes:	fg.avail[i].InBytes(),
				OutBytes:	fg.avail[i].OutBytes(),
				Maps:	mapstr,
				GroupName:	fg.name,
				GroupStrategy:	fg.config.Strategy,
			}
			if (index==0 || index==fg.avail[i].FID()) && (url =="" || strings.Contains(fg.avail[i].URL(), url)) && (enabled =="" || bb==fg.avail[i].Enabled()) && (prio==-1 || uint32(prio)==fg.avail[i].Priority()) {
				if _, ok := aa[fg.avail[i].FID()]; !ok {
					pstatus=append(pstatus, status)
					aa[fg.avail[i].FID()]=true
				}
			}

		}
	}

	return pstatus
}



func (p *Proxy) OperateMain(id uint32, url, enabled string, prio int, op ,stat string) []ProxyStatus{
	pstatus:=[]ProxyStatus{}
	aa:=make(map[uint32]bool)
	bb:=false
	if enabled!="0" || enabled=="true" {
		bb=true
	}

	for i := 0; i < len(p.main.fwdrs); i++ {
		mapstr:=p.MatchRoutes(p.main)
		if mapstr=="" {
			mapstr="[0/0]"
		}
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
				InBytes:	p.main.fwdrs[i].InBytes(),
				OutBytes:	p.main.fwdrs[i].OutBytes(),
				Maps:	mapstr,
				GroupName:	p.main.name,
				GroupStrategy:	p.main.config.Strategy,
		}
		if (id==0 || id==p.main.fwdrs[i].FID()) && (url =="" || strings.Contains(p.main.fwdrs[i].URL(), url)) && (enabled =="" || bb==p.main.fwdrs[i].Enabled()) && (prio==-1 || uint32(prio)==p.main.fwdrs[i].Priority()) {
			switch op {
				case "enable":
					p.main.fwdrs[i].MEnable()
					status.MDisabled=false
					status.Enabled=true
				case "disable":
					p.main.fwdrs[i].MDisable()
					status.MDisabled=true
					status.Enabled=false
				case "setpriority":
					pri,err:=strconv.Atoi(stat)
					if err==nil {
						p.main.fwdrs[i].SetPriority(uint32(pri))
						status.Priority=p.main.fwdrs[i].Priority()
					}
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
			mapstr:=p.MatchRoutes(fg)
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
				InBytes:	fg.fwdrs[i].InBytes(),
				OutBytes:	fg.fwdrs[i].OutBytes(),
				Maps:	mapstr,
				GroupName:	fg.name,
				GroupStrategy:	fg.config.Strategy,
			}
			if (id==0 || id==fg.fwdrs[i].FID()) && (url =="" || strings.Contains(fg.fwdrs[i].URL(), url)) && (enabled =="" || bb==fg.fwdrs[i].Enabled()) && (prio==-1 || uint32(prio)==fg.fwdrs[i].Priority()) {
				switch op {
					case "enable":
						fg.fwdrs[i].MEnable()
						status.MDisabled=false
						status.Enabled=true
					case "disable":
						fg.fwdrs[i].MDisable()
						status.MDisabled=true
						status.Enabled=false
					case "setpriority":
						pri,err:=strconv.Atoi(stat)
						if err==nil {
							fg.fwdrs[i].SetPriority(uint32(pri))
							status.Priority=fg.fwdrs[i].Priority()
						}
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



func (p *Proxy) SetCheckNow(id uint32, url, enabled string, prio int) {
	bb:=false
	if enabled!="0" || enabled=="true" {
		bb=true
	}

	for i := 0; i < len(p.main.fwdrs); i++ {
		if (id==0 || id==p.main.fwdrs[i].FID()) && (url =="" || strings.Contains(p.main.fwdrs[i].URL(), url)) && (enabled =="" || bb==p.main.fwdrs[i].Enabled()) && (prio==-1 || uint32(prio)==p.main.fwdrs[i].Priority()) {
			p.main.fwdrs[i].SetCheckNow()
			
		}

	}
	for _,fg := range p.all {	
		for i := 0; i < len(fg.fwdrs); i++ {
			if (id==0 || id==fg.fwdrs[i].FID()) && (url =="" || strings.Contains(fg.fwdrs[i].URL(), url)) && (enabled =="" || bb==fg.fwdrs[i].Enabled()) && (prio==-1 || uint32(prio)==fg.fwdrs[i].Priority()) {
				fg.fwdrs[i].SetCheckNow()
				
			}

		}
	}

	return 
}