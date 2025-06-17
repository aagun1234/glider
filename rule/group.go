package rule

import (
	"errors"
	"hash/fnv"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"math/rand"

	"github.com/aagun1234/glider/pkg/log"
	"github.com/aagun1234/glider/proxy"
)

// forwarder slice orderd by priority.
type priSlice []*Forwarder

func (p priSlice) Len() int           { return len(p) }
func (p priSlice) Less(i, j int) bool { return p[i].Priority() > p[j].Priority() }
func (p priSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// FwdrGroup is a forwarder group.
type FwdrGroup struct {
	name     string
	config   *Strategy
	//config   Strategy
	fwdrs    priSlice
	avail    []*Forwarder // available forwarders
	mu       sync.RWMutex
	index    uint32
	priority uint32
	totalWeight float64
	Lweights  []float64
	next     func(addr string) *Forwarder
}

// NewFwdrGroup returns a new forward group.
func NewFwdrGroup(rulePath string, s []string, c *Strategy) *FwdrGroup {
	var fwdrs []*Forwarder
	cc := *c
	for _, chain := range s {
		fwdr, err := ForwarderFromURL(chain, cc.IntFace,
			time.Duration(cc.DialTimeout)*time.Second, time.Duration(cc.RelayTimeout)*time.Second)
		if err != nil {
			log.Fatal(err)
		}
		fwdr.SetMaxFailures(uint32(cc.MaxFailures))
		fwdrs = append(fwdrs, fwdr)
	}

	if len(fwdrs) == 0 {
		// direct forwarder
		direct, err := DirectForwarder(cc.IntFace,
			time.Duration(cc.DialTimeout)*time.Second, time.Duration(cc.RelayTimeout)*time.Second)
		if err != nil {
			log.Fatal(err)
		}
		rand.Seed(time.Now().UnixNano())
		direct.fid=rand.Uint32()
		fwdrs = append(fwdrs, direct)
		cc.Strategy = "rr"
	}

	name := strings.TrimSuffix(filepath.Base(rulePath), filepath.Ext(rulePath))
	log.F("[group] newFwdrGroup rulePath %s , %s. ", rulePath, name)
	return newFwdrGroup(name, fwdrs, &cc)
}

// newFwdrGroup returns a new FwdrGroup.
func newFwdrGroup(name string, fwdrs []*Forwarder, c *Strategy) *FwdrGroup {
	p := &FwdrGroup{name: name, fwdrs: fwdrs, config: c}
	log.F("[group] newFwdrGroup %s. ", name)
	sort.Sort(p.fwdrs)

	p.init()

	// default scheduler
	p.next = p.scheduleRR

	// if there're more than 1 forwarders, we care about the strategy.
	if count := len(fwdrs); count > 1 {
		switch c.Strategy {
		case "rr":
			p.next = p.scheduleRR
			log.F("[strategy] %s: %d forwarders forward in round robin mode.", name, count)
		case "prr":
			p.next = p.schedulePRR
			log.F("[strategy] %s: %d forwarders forward in priority based round robin mode,using priority as weight.", name, count)
		case "lrr":
			p.next = p.scheduleLRR
			log.F("[strategy] %s: %d forwarders forward in latency based round robin mode,using priority as weight.", name, count)
		case "ha":
			p.next = p.scheduleHA
			log.F("[strategy] %s: %d forwarders forward in high availability mode.", name, count)
		case "lha":
			p.next = p.scheduleLHA
			log.F("[strategy] %s: %d forwarders forward in latency based high availability mode.", name, count)
		case "dh":
			p.next = p.scheduleDH
			log.F("[strategy] %s: %d forwarders forward in destination hashing mode.", name, count)
		default:
			p.next = p.scheduleRR
			log.F("[strategy] %s: not supported forward mode '%s', use round robin mode for %d forwarders.", name, c.Strategy, count)
		}
	}

	for _, f := range fwdrs {
		f.AddHandler(p.onStatusChanged)
	}

	return p
}

// Dial connects to the address addr on the network net.
func (p *FwdrGroup) Dial(network, addr string) (net.Conn, proxy.Dialer, error) {
	nd := p.NextDialer(addr)
	c, err := nd.Dial(network, addr)
	return c, nd, err
}

// DialUDP connects to the given address.
func (p *FwdrGroup) DialUDP(network, addr string) (pc net.PacketConn, dialer proxy.UDPDialer, err error) {
	nd := p.NextDialer(addr)
	pc, err = nd.DialUDP(network, addr)
	return pc, nd, err
}

// NextDialer returns the next dialer.
func (p *FwdrGroup) NextDialer(dstAddr string) proxy.Dialer {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.avail) == 0 {
		return p.fwdrs[atomic.AddUint32(&p.index, 1)%uint32(len(p.fwdrs))]
	}

	return p.next(dstAddr)
}

// Priority returns the active priority of dialer.
func (p *FwdrGroup) Priority() uint32 { return atomic.LoadUint32(&p.priority) }

// SetPriority sets the active priority of daler.
func (p *FwdrGroup) SetPriority(pri uint32) { atomic.StoreUint32(&p.priority, pri) }

// init traverse d.fwdrs and init the available forwarder slice.
func (p *FwdrGroup) init() {
	for _, f := range p.fwdrs {
		if f.Enabled() {
			p.SetPriority(f.Priority())
			log.F("[group] %s: Init SetPriority %d.", p.name, f.Priority())
			break
		}
	}
	
	aa:=uint32(1)
	if p.config.Strategy == "prr" {
		aa=uint32(p.config.PriorityStep)
	} else {
		aa=1
	}
	log.F("[group] %s: onStatusChanged config.Strategy %s, Priority Step=%d. ", p.name, p.config.Strategy, aa)
	p.avail = nil
	for _, f := range p.fwdrs {
		if f.Enabled() && uint32((f.Priority()+aa-1)/aa) >= uint32((p.Priority()+aa-1)/aa) {
			log.F("[group] %s: Init Add availble %d. FwdrGroupPriority = %d, FwdrPriority = %d", p.name, f.FID(), p.Priority(), f.Priority())
			p.avail = append(p.avail, f)
		}
	}

	if len(p.avail) == 0 {
		// no available forwarders, set priority to 0 to check all forwarders in check func
		p.SetPriority(0)
		// log.F("[group] no available forwarders, please check your config file or network settings")
	}
}

// onStatusChanged will be called when fwdr's status changed.
func (p *FwdrGroup) onStatusChanged(fwdr *Forwarder) {
	p.mu.Lock()
	defer p.mu.Unlock()
	aa :=uint32(1)
	if fwdr.Enabled() {
		if p.config.Strategy == "prr" {
			aa=uint32(p.config.PriorityStep)
		} else {
			aa=1
		}
		log.F("[group] %s: onStatusChanged config.Strategy %s, Priority Step=%d. ", p.name, p.config.Strategy, aa)
		if uint32((fwdr.Priority()+aa-1)/aa) == uint32((p.Priority()+aa-1)/aa) {
			p.avail = append(p.avail, fwdr)
			log.F("[group] %s: onStatusChanged Add available %d. FwdrGroupPriority = %d, FwdrPriority = %d", p.name, fwdr.FID(),p.Priority(),fwdr.Priority())
		} else if uint32((fwdr.Priority()+aa-1)/aa) > uint32((p.Priority()+aa-1)/aa) {
			log.F("[group] %s: onStatusChanged init with FID %d. FwdrGroupPriority = %d, FwdrPriority = %d", p.name, fwdr.FID(),p.Priority(),fwdr.Priority())
			//set A larger Priority in init
			p.init()
		}
		log.F("[group] %s: %s(%d) changed status from DISABLED to ENABLED (%d of %d currently enabled)",
			p.name, fwdr.Addr(), fwdr.Priority(), len(p.avail), len(p.fwdrs))
	} else {
		for i, f := range p.avail {
			if f == fwdr {
				p.avail[i], p.avail = p.avail[len(p.avail)-1], p.avail[:len(p.avail)-1]
				log.F("[group] %s: onStatusChanged Remove available %d.", p.name, fwdr.FID())
				break
			}
		}
		log.F("[group] %s: %s(%d) changed status from ENABLED to DISABLED (%d of %d currently enabled)",
			p.name, fwdr.Addr(), fwdr.Priority(), len(p.avail), len(p.fwdrs))
	}

	if len(p.avail) == 0 {
		log.F("[group] %s: onStatusChanged No available Fwdrs, calling init.", p.name)
		p.init()
	}
}

// Check runs the forwarder checks.
func (p *FwdrGroup) Check() {
	if len(p.fwdrs) == 1 {
		log.F("[group] %s: only 1 forwarder found, disable health checking", p.name)
		p.fwdrs[0].MEnable() 
		return
	}

	if !strings.Contains(p.config.Check, "://") {
		p.config.Check += "://"
	}

	u, err := url.Parse(p.config.Check)
	if err != nil {
		log.F("[group] %s: parse check config error: %s, disable health checking", p.name, err)
		return
	}

	addr := u.Host
	timeout := time.Duration(p.config.CheckTimeout) * time.Second

	var checker Checker
	switch u.Scheme {
	case "tcp":
		checker = newTcpChecker(addr, timeout)
	case "http", "https":
		expect := "HTTP" // default: check the first 4 chars in response
		params, _ := url.ParseQuery(u.Fragment)
		if ex := params.Get("expect"); ex != "" {
			expect = ex
		}
		checker = newHttpChecker(addr, u.RequestURI(), expect, timeout, u.Scheme == "https")
	case "file":
		checker = newFileChecker(u.Host + u.Path)
	default:
		log.F("[group] %s: unknown scheme in check config `%s`, disable health checking", p.name, p.config.Check)
		return
	}

	log.F("[group] %s: using check config: %s", p.name, p.config.Check)

	for i := 0; i < len(p.fwdrs); i++ {
		go p.check(p.fwdrs[i], checker)
	}
}

func (p *FwdrGroup) check(fwdr *Forwarder, checker Checker) {
	wait := uint8(0)
	fwdr.SetChkCount(0)
	fwdr.SetTotalFails(0)
	fwdr.SetFailures(0)
	aa:=uint32(1)
	//intval := time.Duration(p.config.CheckInterval) * time.Second
	if p.config.Strategy=="prr" {
		aa=uint32(p.config.PriorityStep)
	} else {
		aa=1
	}
	log.F("[group] %s: check (%d) started config.Strategy %s, Priority Step=%d. ", p.name, fwdr.FID(), p.config.Strategy, aa)
	for {
		ii:=0
		for ii<=(p.config.CheckInterval*int(wait/2)) {
			if fwdr.GetCheckNow() {
				break
			}
			ii++
			time.Sleep(time.Duration(1) * time.Second)
		}

		// check all forwarders at least one time
		if wait > 0 && (uint32((fwdr.Priority()+aa-1)/aa) < uint32((p.Priority()+aa-1)/aa)) && !(p.config.CheckLowerPriority) {
			log.F("[Check] %s: skip check %d with CheckLowerPriority.", p.name, fwdr.FID())
			continue
		}

		if fwdr.Enabled() && p.config.CheckDisabledOnly {
			log.F("[Check] %s: skip check %d with CheckDisabledOnly.", p.name, fwdr.FID())
			continue
		}
		
		if fwdr.MDisabled() {
			log.F("[Check] %s: skip check %d with MDisabled.", p.name, fwdr.FID())
			continue
		}

		elapsed, err := checker.Check(fwdr)
		fwdr.IncChkCount()
		if err != nil {
			if errors.Is(err, proxy.ErrNotSupported) {
				fwdr.SetMaxFailures(0)
				log.F("[check] %s: %s(%d), %s, stop checking", p.name, fwdr.Addr(), fwdr.Priority(), err)
				fwdr.Enable()
				break
			}

			wait++
			if wait > 6 {
				wait = 6
			}

			log.F("[check] %s: %s(%d), FAILED. error: %s", p.name, fwdr.Addr(), fwdr.Priority(), err)
			fwdr.Disable()
			
			continue
		}

		wait = 2
		if uint32((fwdr.Priority()+aa-1)/aa) < uint32((p.Priority()+aa-1)/aa) {
			wait = 6
		}
		p.setLatency(fwdr, elapsed)
		log.F("[check] %s: %s(%d), SUCCESS. Elapsed: %dms, Latency: %dms.",
			p.name, fwdr.Addr(), fwdr.Priority(), elapsed.Milliseconds(), time.Duration(fwdr.Latency()).Milliseconds())
		if !fwdr.MDisabled() {
			fwdr.Enable()
		}
	}
}

func (p *FwdrGroup) setLatency(fwdr *Forwarder, elapsed time.Duration) {
	newLatency := int64(elapsed)
	if cnt := p.config.CheckLatencySamples; cnt > 1 {
		if lastLatency := fwdr.Latency(); lastLatency > 0 {
			newLatency = (lastLatency*(int64(cnt)-1) + int64(elapsed)) / int64(cnt)
		}
	}
	fwdr.SetLatency(newLatency)
}

// Round Robin.
func (p *FwdrGroup) scheduleRR(dstAddr string) *Forwarder {
	return p.avail[atomic.AddUint32(&p.index, 1)%uint32(len(p.avail))]
}

// Priority based Round Robin.
func (p *FwdrGroup) schedulePRR1(dstAddr string) *Forwarder {
	if len(p.avail) == 0 {
	return nil
	}

	totalWeight := int64(0)
	for _, fwdr := range p.avail {
		totalWeight += int64(fwdr.Priority())
	}

	rand.Seed(time.Now().UnixNano())
	r := rand.Int63n(totalWeight)

	sum := int64(0)
	for i := range p.avail {
		sum += int64(p.avail[i].Priority())
		if r < sum {
			atomic.StoreUint32(&p.index, uint32(i))
			log.F("[schedulePRR] %s: Next forwarder %d (%d), Priority %d.", p.name, p.avail[i].FID(), i, p.avail[i].Priority())
			return p.avail[i]
		}
	}

	return p.avail[0]
}

func (p *FwdrGroup) schedulePRR(dstAddr string) *Forwarder {
//	p.mu.Lock()
//	defer p.mu.Unlock()

	if len(p.avail) == 0 {
		return nil
	}

	// 如果 totalWeight 未初始化或 avail 发生变化，则重新计算 totalWeight
	if p.totalWeight == 0 || len(p.avail) != int(atomic.LoadUint32(&p.index)) {
		p.totalWeight = 0
		for _, fwdr := range p.avail {
			p.totalWeight += float64(fwdr.Priority())
		}
	}

	rand.Seed(time.Now().UnixNano())
	r := rand.Int63n(int64(p.totalWeight))

	sum := int64(0)
	lastIndex := int(atomic.LoadUint32(&p.index))
	startIndex := lastIndex + 1
	if startIndex >= len(p.avail) {
		startIndex = 0
	}

	for i := range p.avail {
		idx := (startIndex + i) % len(p.avail)
		sum += int64(p.avail[idx].Priority())
		if r < sum {
			atomic.StoreUint32(&p.index, uint32(idx))
			log.F("[schedulePRR] %s: Next forwarder %d (%d), Priority %d.", p.name, p.avail[idx].FID, idx, p.avail[idx].Priority())
			return p.avail[idx]
		}
	}

	return p.avail[0]
}

// Latency based Round Robin.

func (p *FwdrGroup) scheduleLRR1(dstAddr string) *Forwarder {

	if len(p.avail) == 0 {
		return nil
	}

	// 1. 计算权重（将延迟转换为权重）
	weights := make([]float64, len(p.avail))
	totalWeight := 0.0

	for i := range p.avail {
		latency := float64(p.avail[i].Latency_ms())
		// 延迟越小权重越高，这里使用反比关系
		// 加1避免除以0，使用平方使权重差异更明显
		weight := 1.0 / (latency + 1) 
		weights[i] = weight*weight
		totalWeight += weight*weight
	}

	// 2. 生成随机数并选择
	rand.Seed(time.Now().UnixNano())
	r := rand.Float64() * totalWeight
	
	// 3. 根据权重选择元素
	cumulativeWeight := 0.0
	for i := range p.avail {
		cumulativeWeight += weights[i]
		if r <= cumulativeWeight {
			atomic.StoreUint32(&p.index, uint32(i))  // 更新当前索引（如果需要）
			log.F("[scheduleLRR] %s: Next forwarder %d (index: %d), latency %d ms.", p.name, p.avail[i].FID(), i, p.avail[i].Latency_ms())
			return p.avail[i]
		}
	}

	// 如果由于浮点精度问题没选中，返回第一个

	return p.avail[0]
}

func (p *FwdrGroup) scheduleLRR(dstAddr string) *Forwarder {
//	p.mu.Lock()
//	defer p.mu.Unlock()

	if len(p.avail) == 0 {
		return nil
	}

	// 如果权重未计算或长度不匹配，则重新计算权重
	if len(p.Lweights) != len(p.avail) || p.totalWeight == 0 {
		p.recalculateLWeights()
	}

	// 使用稳定的随机数生成器
	r := rand.Float64() * p.totalWeight

	// 根据权重选择元素
	cumulativeWeight := 0.0
	for idx := range p.avail {
		cumulativeWeight += p.Lweights[idx]
		if r <= cumulativeWeight {
			atomic.StoreUint32(&p.index, uint32(idx)) // 更新当前索引（如果需要）
			log.F("[scheduleLRR] %s: Next forwarder %d (index: %d), latency %d ms.", p.name, p.avail[idx].FID(), idx, p.avail[idx].Latency_ms())
			return p.avail[idx]
		}
	}

	// 如果由于浮点精度问题没选中，返回第一个
	return p.avail[0]
}


func (p *FwdrGroup) recalculateLWeights() {
	weights := make([]float64, len(p.avail))
	totalWeight := 0.0

	for i := range p.avail {
		latency := float64(p.avail[i].Latency_ms())
		weight := 1.0 / (latency + 1)
		weights[i] = weight*weight
		totalWeight += weight*weight
	}

	p.Lweights = weights
	p.totalWeight = totalWeight
}


// High Availability.
func (p *FwdrGroup) scheduleHA(dstAddr string) *Forwarder {
	return p.avail[0]
}

// Latency based High Availability.
func (p *FwdrGroup) scheduleLHA(dstAddr string) *Forwarder {
	oldfwdr, newfwdr := p.avail[0], p.avail[0]
	lowest := oldfwdr.Latency()
	for _, f := range p.avail {
		if f.Latency() < lowest {
			lowest = f.Latency()
			newfwdr = f
		}
	}
	tolerance := int64(p.config.CheckTolerance) * int64(time.Millisecond)
	if newfwdr.Latency() < (oldfwdr.Latency() - tolerance) {
		return newfwdr
	}
	return oldfwdr
}

// Destination Hashing.
func (p *FwdrGroup) scheduleDH(dstAddr string) *Forwarder {
	fnv1a := fnv.New32a()
	fnv1a.Write([]byte(dstAddr))
	return p.avail[fnv1a.Sum32()%uint32(len(p.avail))]
}
