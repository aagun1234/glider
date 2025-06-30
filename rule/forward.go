package rule

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"math/rand"

	"github.com/aagun1234/glider/pkg/log"
	"github.com/aagun1234/glider/proxy"
)

// StatusHandler function will be called when the forwarder's status changed.
type StatusHandler func(*Forwarder)

// Forwarder associates with a `-forward` command, usually a dialer or a chain of dialers.
type Forwarder struct {
	proxy.Dialer
	fid			uint32
	url         string
	addr        string
	priority    uint32
	maxFailures uint32 // maxfailures to set to Disabled
	disabled    uint32
	mdisabled	uint32
	failures    uint32
	totalfails	uint32
	chkcount	uint32
	checknow	uint32
	latency     int64
	Inbytes		uint64
	Outbytes	uint64
	intface     string // local interface or ip address
	handlers    []StatusHandler
}

func generateUnique32Bit() uint32 {
	rand.Seed(time.Now().UnixNano())
	timestamp := uint32(time.Now().UnixNano() / 1000000) // 毫秒级时间戳
	randomPart := uint32(rand.Intn(999))                  // 随机部分
	uniqueValue := (timestamp % (1<<31)) + randomPart     // 确保结果在32位范围内
	return uniqueValue % (1 << 31)
}
// ForwarderFromURL parses `forward=` command value and returns a new forwarder.
func ForwarderFromURL(s, intface string, dialTimeout, relayTimeout time.Duration) (f *Forwarder, err error) {
	f = &Forwarder{url: s}
	
	f.fid=generateUnique32Bit()

	ss := strings.Split(s, "#")
	if len(ss) > 1 {
		err = f.parseOption(ss[1])
	}

	iface := intface
	if f.intface != "" && f.intface != intface {
		iface = f.intface
	}

	var d proxy.Dialer
	d, err = proxy.NewDirect(iface, dialTimeout, relayTimeout)
	if err != nil {
		return nil, err
	}

	var addrs []string
	for _, url := range strings.Split(ss[0], ",") {
		d, err = proxy.DialerFromURL(url, d)
		if err != nil {
			return nil, err
		}
		cnt := len(addrs)
		if cnt == 0 ||
			(cnt > 0 && d.Addr() != addrs[cnt-1]) {
			addrs = append(addrs, d.Addr())
		}
	}

	f.Dialer = d
	f.addr = d.Addr()

	if len(addrs) > 0 {
		f.addr = strings.Join(addrs, ",")
	}

	// set forwarder to disabled by default
	f.Disable()

	return f, err
}

// DirectForwarder returns a direct forwarder.
func DirectForwarder(intface string, dialTimeout, relayTimeout time.Duration) (*Forwarder, error) {
	d, err := proxy.NewDirect(intface, dialTimeout, relayTimeout)

	if err != nil {
		return nil, err
	}
	return &Forwarder{Dialer: d, addr: d.Addr()}, nil
}

func (f *Forwarder) parseOption(option string) error {
	query, err := url.ParseQuery(option)
	if err != nil {
		return err
	}

	var priority uint64
	p := query.Get("priority")
	if p != "" {
		priority, err = strconv.ParseUint(p, 10, 32)
	}
	f.SetPriority(uint32(priority))

	f.intface = query.Get("interface")

	return err
}

// Addr returns the forwarder's addr.
// NOTE: addr returns for chained dialers: dialer1Addr,dialer2Addr,...
func (f *Forwarder) Addr() string {
	return f.addr
}

// URL returns the forwarder's full url.
func (f *Forwarder) URL() string {
	return f.url
}

// Dial dials to addr and returns conn.
func (f *Forwarder) Dial(network, addr string) (c net.Conn, err error) {
	c, err = f.Dialer.Dial(network, addr)
	if err != nil {
		f.IncFailures()
	}
	return c, err
}


func (f *Forwarder) IncChkCount() {
	atomic.AddUint32(&f.chkcount, 1)
}
func (f *Forwarder) SetChkCount(v uint32) {
	atomic.StoreUint32(&f.chkcount, v)
}
// get bytes
func (f *Forwarder) ChkCount() uint32{
	return atomic.LoadUint32(&f.chkcount)
}

func (f *Forwarder) SetCheckNow() {
	atomic.StoreUint32(&f.checknow, 1)
}
// get bytes
func (f *Forwarder) GetCheckNow()  bool {
	if isTrue(atomic.LoadUint32(&f.checknow)) {
		atomic.StoreUint32(&f.checknow, 0)
		return true
	} else {
		return false
	}
}


// Failures returns the failuer count of forwarder.
func (f *Forwarder) FID() uint32 {
	return atomic.LoadUint32(&f.fid)
}
// Failures returns the failuer count of forwarder.
func (f *Forwarder) Failures() uint32 {
	return atomic.LoadUint32(&f.failures)
}
// Failures returns the failuer count of forwarder.
func (f *Forwarder) TotalFails() uint32 {
	return atomic.LoadUint32(&f.totalfails)
}
func (f *Forwarder) SetTotalFails(v uint32) {
	atomic.StoreUint32(&f.totalfails, v)
}

// IncFailures increase the failuer count by 1.
func (f *Forwarder) IncFailures() {
	atomic.AddUint32(&f.totalfails, 1)
	failures := atomic.AddUint32(&f.failures, 1)
	if f.MaxFailures() == 0 {
		return
	}

	// log.F("[forwarder] %s(%d) recorded %d failures, maxfailures: %d", f.addr, f.Priority(), failures, f.MaxFailures())

	if failures == f.MaxFailures() && f.Enabled() {
		log.Printf("[forwarder] %s(%d) reaches maxfailures: %d, put offline", f.addr, f.Priority(), f.MaxFailures())
		f.Disable()
	}
}


// add bytes
func (f *Forwarder) AddInBytes(v uint64) {
	atomic.AddUint64(&f.Inbytes, v)
}

func (f *Forwarder) AddOutBytes(v uint64) {
	atomic.AddUint64(&f.Outbytes, v)
}
// get bytes
func (f *Forwarder) InBytes() uint64{
	return atomic.LoadUint64(&f.Inbytes)
}

func (f *Forwarder) OutBytes() uint64{
	return atomic.LoadUint64(&f.Outbytes)

}


// Set Failures count by v.
func (f *Forwarder) SetFailures(v uint32) {
	atomic.StoreUint32(&f.failures, v)
}


// AddHandler adds a custom handler to handle the status change event.
func (f *Forwarder) AddHandler(h StatusHandler) {
	f.handlers = append(f.handlers, h)
}

// Enable the forwarder.
func (f *Forwarder) Enable() {
	atomic.StoreUint32(&f.failures, 0)
	if atomic.CompareAndSwapUint32(&f.disabled, 1, 0) {
		for _, h := range f.handlers {
			h(f)
		}
	}
}

// Disable the forwarder.
func (f *Forwarder) Disable() {
	if atomic.CompareAndSwapUint32(&f.disabled, 0, 1) {
		for _, h := range f.handlers {
			h(f)
		}
	}
}

// Enable the forwarder.
func (f *Forwarder) MEnable() {
	if atomic.CompareAndSwapUint32(&f.mdisabled, 1, 0) {
		if atomic.CompareAndSwapUint32(&f.disabled, 1, 0) {
			atomic.StoreUint32(&f.failures, 0)
			for _, h := range f.handlers {
				h(f)
			}
		}
	}

}

// Disable the forwarder.
func (f *Forwarder) MDisable() {
	if atomic.CompareAndSwapUint32(&f.mdisabled, 0, 1) {
		for _, h := range f.handlers {
			h(f)
		}
	}
}

// Enabled returns the status of forwarder.
func (f *Forwarder) Enabled() bool {
	if !isTrue(atomic.LoadUint32(&f.mdisabled)) {
		return !isTrue(atomic.LoadUint32(&f.disabled))
	} else {
		return !isTrue(atomic.LoadUint32(&f.mdisabled))
	}
}

// Enabled returns the status of forwarder.
func (f *Forwarder) MDisabled() bool {
	return isTrue(atomic.LoadUint32(&f.mdisabled))
	
}

func isTrue(n uint32) bool {
	return n&1 == 1
}

// Priority returns the priority of forwarder.
func (f *Forwarder) Priority() uint32 {
	return atomic.LoadUint32(&f.priority)
}

// SetPriority sets the priority of forwarder.
func (f *Forwarder) SetPriority(l uint32) {
	atomic.StoreUint32(&f.priority, l)
}

// MaxFailures returns the maxFailures of forwarder.
func (f *Forwarder) MaxFailures() uint32 {
	return atomic.LoadUint32(&f.maxFailures)
}

// SetMaxFailures sets the maxFailures of forwarder.
func (f *Forwarder) SetMaxFailures(l uint32) {
	atomic.StoreUint32(&f.maxFailures, l)
}

// Latency returns the latency of forwarder.
func (f *Forwarder) Latency() int64 {
	return atomic.LoadInt64(&f.latency)
}

// Latency returns the latency of forwarder.
func (f *Forwarder) Latency_ms() int64 {
	return atomic.LoadInt64(&f.latency)/int64(time.Millisecond)
}

// SetLatency sets the latency of forwarder.
func (f *Forwarder) SetLatency(l int64) {
	atomic.StoreInt64(&f.latency, l)
}
