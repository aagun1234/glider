package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aagun1234/glider/dns"
	"github.com/aagun1234/glider/ipset"
	"github.com/aagun1234/glider/pkg/log"
	"github.com/aagun1234/glider/proxy"
	"github.com/aagun1234/glider/rule"
	"github.com/aagun1234/glider/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	version = "0.17.b"
	config  = parseConfig()
)

func main() {
	// global rule proxy
	pxy := rule.NewProxy(config.Forwards, &config.Strategy, config.rules)
	pxy.SetRateLimit(config.RateLimit)

	prom_init()

	// ipset manager
	ipsetM, _ := ipset.NewManager(config.rules)

	// check and setup dns server
	if config.DNS != "" {
		d, err := dns.NewServer(config.DNS, pxy, &config.DNSConfig)
		if err != nil {
			log.Fatal(err)
		}

		// rules
		for _, r := range config.rules {
			if len(r.DNSServers) > 0 {
				for _, domain := range r.Domain {
					d.SetServers(domain, r.DNSServers)
				}
			}
		}

		// add a handler to update proxy rules when a domain resolved
		d.AddHandler(pxy.AddDomainIP)
		if ipsetM != nil {
			d.AddHandler(ipsetM.AddDomainIP)
		}

		d.Start()

		// custom resolver
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Second * 3}
				return d.DialContext(ctx, "udp", config.DNS)
			},
		}
	}

	for _, r := range config.rules {
		r.IP, r.CIDR, r.Domain = nil, nil, nil
	}

	// enable checkers
	pxy.Check()
	//start status api server
	if config.StatusServer != "" {
		go startServer(pxy, config.StatusServer, config.StatusACL)
	}

	// run proxy servers
	for _, listen := range config.Listens {
		local, err := proxy.ServerFromURL(listen, pxy)
		if err != nil {
			log.Fatal(err)
		}
		go local.ListenAndServe()
	}

	// run services
	for _, s := range config.Services {
		service, err := service.New(s)
		if err != nil {
			log.Fatal(err)
		}
		go service.Run()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

//--- http://127.0.0.1:8880/status?id=2387120117
//--- http://127.0.0.1:8880/status?available=1
//--- http://127.0.0.1:8880/status?available=true
//--- http://127.0.0.1:8880/status?enabled=1
//--- http://127.0.0.1:8880/status?enabled=0
//--- http://127.0.0.1:8880/status?url=127.0.0.1:3789
//--- http://127.0.0.1:8880/status?id=2387120117&url=127.0.0.1:3789&enabled=1
//--- http://127.0.0.1:8880/operation?url=127.0.0.1:37891&op=enable
//--- http://127.0.0.1:8880/operation?url=127.0.0.1:37891&op=disable
//--- http://127.0.0.1:8880/operation?url=127.0.0.1:37891&op=check
//--- http://127.0.0.1:8880/operation?url=127.0.0.1&op=disable
//--- http://127.0.0.1:8880/operation?op=check
//---
//  比如可以curl -s 'http://127.0.0.1:8880/status?url=127.0.0.1&available=true' |jq -r '.[].id'
//  check返回的并不是check的结果，而是立即check的forward的信息，结果要等健康检查完成后再查询
//  available的必定是enabled的，disabled的一定不是available的，低优先级的一定不是available的

func startServer(p *rule.Proxy, addr string, acl []string) {

	saddr := addr
	auser := ""
	apass := ""

	if strings.Contains(addr, "@") {
		server1 := strings.Split(addr, "@")
		saddr = server1[1]

		if strings.Contains(server1[0], ":") {
			auth1 := strings.Split(server1[0], ":")
			auser = auth1[0]
			apass = auth1[1]
		} else {
			auser = server1[0]
			apass = ""
		}
	}

	// 定义HTTP处理函数
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		handler1(w, r, p, auser, apass, acl)
	})
	http.HandleFunc("/operation", func(w http.ResponseWriter, r *http.Request) {
		handler2(w, r, p, auser, apass, acl)
	})
	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		handler3(w, r, config, auser, apass, acl)
	})
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		handler4(w, r, p, auser, apass, acl)
	})

	// 启动HTTP服务器
	fmt.Printf("Status Server is listening on %s...\n", saddr)
	//log.F("Status Server is listening on %s...\n", addr)
	if err := http.ListenAndServe(saddr, nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}

// IsIPInSubnets 检查 IP 是否在给定的子网列表中
func IsIPInSubnets(ipStr string, subnets []string) (bool, error) {

	if len(subnets) <= 0 {
		return true, nil
	}

	// 处理带端口的 IP（如 "192.168.1.1:8080"）
	ipStr, _, err := net.SplitHostPort(ipStr)
	if err != nil {
		// 如果没有端口（如直接是 "192.168.1.1"），继续解析
		ipStr = strings.TrimSpace(ipStr)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, err
	}

	for _, subnet := range subnets {

		if strings.Contains(subnet, ",") {
			subnets1 := strings.Split(subnet, ",")
			for _, subnet1 := range subnets1 {
				_, cidr, err := net.ParseCIDR(subnet1)
				if err != nil {
					log.Printf("[main] Check ACL error: %s", err)
					continue
				}

				if cidr.Contains(ip) {
					return true, nil
				}
			}
		} else {
			_, cidr, err := net.ParseCIDR(subnet)
			if err != nil {
				log.Printf("[main] Check ACL error: %s", err)
				return false, err
			}

			if cidr.Contains(ip) {
				return true, nil
			}
		}
	}

	return false, nil
}

// 处理HTTP请求的函数
func handler1(w http.ResponseWriter, r *http.Request, pxy *rule.Proxy, user, pass string, acl []string) {

	ip := r.RemoteAddr
	isAllowed, err := IsIPInSubnets(ip, acl)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !isAllowed {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		log.Printf("[main] StatusServer: Unauthorized from %s", r.RemoteAddr)
		return
	}

	pstatus := []rule.ProxyStatus{}
	index := 0
	//fmt.Printf("API : %v",r.URL)
	query := r.URL.Query()
	enabled := query.Get("enabled")
	available := query.Get("available")
	url := query.Get("url")

	index, err = strconv.Atoi(query.Get("id"))
	if err != nil {
		index = 0
	}
	prio, err1 := strconv.Atoi(query.Get("priority"))
	if err1 != nil {
		prio = -1
	}

	if user != "" {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("[main] StatusServer: %s:%s Unauthorized from %s", username, password, r.RemoteAddr)
			return
		}

		// 验证用户名和密码
		if username != user || password != pass {
			http.Error(w, "Unauthorized for "+username+":"+password, http.StatusUnauthorized)
			log.Printf("[main] StatusServer: %s:%s Unauthorized from %s", username, password, r.RemoteAddr)
			return
		}
	}

	// 设置响应头为JSON格式
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 创建要返回的JSON数据
	if available == "1" || available == "true" {
		pstatus = pxy.GetAvailStatus(uint32(index), url, enabled, prio)
	} else {
		pstatus = pxy.GetMainStatus(uint32(index), url, enabled, prio)
	}
	// 将结构体数组编码为JSON并写入响应
	if err := json.NewEncoder(w).Encode(pstatus); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

var (
	proxyStatusDesc = prometheus.NewDesc(
		"glider_status",
		"Status information of glider servers",
		[]string{"url", "groupname", "priority", "enabled", "manual_disabled"},
		nil,
	)

	proxyMetrics = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "glider_metrics",
			Help: "Detailed metrics of glider servers",
		},
		[]string{"url", "groupname", "priority", "enabled", "manual_disabled", "metric"},
	)

	runtimeGoroutines = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "glider_goroutines_total",
		Help: "Number of goroutines currently running",
	})

	runtimeMemStats = struct {
		Alloc      prometheus.Gauge
		TotalAlloc prometheus.Gauge
		Sys        prometheus.Gauge
		HeapAlloc  prometheus.Gauge
	}{
		Alloc: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "glider_memory_alloc_bytes",
			Help: "Currently allocated heap memory in bytes",
		}),
		TotalAlloc: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "glider_memory_total_alloc_bytes",
			Help: "Total heap memory allocated (cumulative)",
		}),
		Sys: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "glider_memory_sys_bytes",
			Help: "Total memory obtained from the OS",
		}),
		HeapAlloc: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "glider_memory_heap_alloc_bytes",
			Help: "Heap memory currently allocated",
		}),
	}
)

type ProxyStatusCollector struct {
	pstatus []rule.ProxyStatus
}

func (c *ProxyStatusCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- proxyStatusDesc
	proxyMetrics.Describe(ch)
}

func (c *ProxyStatusCollector) Collect(ch chan<- prometheus.Metric) {
	for _, ps := range c.pstatus {
		// Export status as a metric (1 for enabled, 0 for disabled)
		status := 0.0
		if ps.Enabled {
			status = 1.0
		}
		enabledStr := "false"
		if ps.Enabled {
			enabledStr = "true"
		}
		mDisabledStr := "false"
		if ps.MDisabled {
			mDisabledStr = "true"
		}

		ch <- prometheus.MustNewConstMetric(
			proxyStatusDesc,
			prometheus.GaugeValue,
			status,
			ps.URL,
			ps.GroupName,
			strconv.Itoa(int(ps.Priority)),
			enabledStr,
			mDisabledStr,
		)

		//		labels := prometheus.Labels{
		//			"url":             ps.URL,
		//			"groupname":       ps.GroupName,
		//			"enabled":         strconv.FormatBool(ps.Enabled),
		//			"priority":        strconv.FormatUint(uint64(ps.Priority), 10),
		//			"manual_disabled": strconv.FormatBool(ps.MDisabled),
		//		}

		// Export detailed metrics using GaugeVec

		proxyMetrics.WithLabelValues(ps.URL, ps.GroupName, strconv.Itoa(int(ps.Priority)), enabledStr, mDisabledStr, "priority").Set(float64(ps.Priority))
		proxyMetrics.WithLabelValues(ps.URL, ps.GroupName, strconv.Itoa(int(ps.Priority)), enabledStr, mDisabledStr, "max_failures").Set(float64(ps.MaxFailures))
		proxyMetrics.WithLabelValues(ps.URL, ps.GroupName, strconv.Itoa(int(ps.Priority)), enabledStr, mDisabledStr, "chkcount").Set(float64(ps.ChkCount))
		proxyMetrics.WithLabelValues(ps.URL, ps.GroupName, strconv.Itoa(int(ps.Priority)), enabledStr, mDisabledStr, "manualy_disabled").Set(boolToFloat(ps.MDisabled))
		proxyMetrics.WithLabelValues(ps.URL, ps.GroupName, strconv.Itoa(int(ps.Priority)), enabledStr, mDisabledStr, "failures").Set(float64(ps.TotalFails))
		proxyMetrics.WithLabelValues(ps.URL, ps.GroupName, strconv.Itoa(int(ps.Priority)), enabledStr, mDisabledStr, "latency").Set(float64(ps.Latency))
		proxyMetrics.WithLabelValues(ps.URL, ps.GroupName, strconv.Itoa(int(ps.Priority)), enabledStr, mDisabledStr, "inbytes").Set(float64(ps.InBytes))
		proxyMetrics.WithLabelValues(ps.URL, ps.GroupName, strconv.Itoa(int(ps.Priority)), enabledStr, mDisabledStr, "outbytes").Set(float64(ps.OutBytes))

		//		proxyMetrics.With(labels).Set(float64(ps.Priority))
		//		proxyMetrics.With(labels).Set(float64(ps.MaxFailures))
		//		proxyMetrics.With(labels).Set(float64(ps.ChkCount))
		//		proxyMetrics.With(labels).Set(boolToFloat(ps.MDisabled))
		//		proxyMetrics.With(labels).Set(float64(ps.TotalFails))
		//		proxyMetrics.With(labels).Set(float64(ps.Latency))
		//		proxyMetrics.With(labels).Set(float64(ps.InBytes))
		//		proxyMetrics.With(labels).Set(float64(ps.OutBytes))
	}

	proxyMetrics.Collect(ch)
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func prom_init() {
	prometheus.MustRegister(proxyMetrics)
	prometheus.MustRegister(runtimeGoroutines)
	prometheus.MustRegister(runtimeMemStats.Alloc)
	prometheus.MustRegister(runtimeMemStats.TotalAlloc)
	prometheus.MustRegister(runtimeMemStats.Sys)
	prometheus.MustRegister(runtimeMemStats.HeapAlloc)

}

func handler4(w http.ResponseWriter, r *http.Request, pxy *rule.Proxy, user, pass string, acl []string) {

	ip := r.RemoteAddr
	isAllowed, err := IsIPInSubnets(ip, acl)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !isAllowed {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		log.Printf("[main] StatusServer: Unauthorized from %s", r.RemoteAddr)
		return
	}

	pstatus := []rule.ProxyStatus{}
	index := 0
	//fmt.Printf("API : %v",r.URL)
	query := r.URL.Query()
	enabled := query.Get("enabled")
	available := query.Get("available")
	url := query.Get("url")

	index, err = strconv.Atoi(query.Get("id"))
	if err != nil {
		index = 0
	}
	prio, err1 := strconv.Atoi(query.Get("priority"))
	if err1 != nil {
		prio = -1
	}

	if user != "" {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			log.Printf("[main] StatusServer: %s:%s Unauthorized from %s", username, password, r.RemoteAddr)
			return
		}

		// 验证用户名和密码
		if username != user || password != pass {
			http.Error(w, "Unauthorized for "+username+":"+password, http.StatusUnauthorized)
			log.Printf("[main] StatusServer: %s:%s Unauthorized from %s", username, password, r.RemoteAddr)
			return
		}
	}

	// 设置响应头为JSON格式
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 创建要返回的JSON数据
	if available == "1" || available == "true" {
		pstatus = pxy.GetAvailStatus(uint32(index), url, enabled, prio)
	} else {
		pstatus = pxy.GetMainStatus(uint32(index), url, enabled, prio)
	}

	// 创建 Prometheus 注册表（避免污染全局注册表）
	registry := prometheus.NewRegistry()

	runtimeGoroutines.Set(float64(runtime.NumGoroutine()))

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	runtimeMemStats.Alloc.Set(float64(memStats.Alloc))
	runtimeMemStats.TotalAlloc.Set(float64(memStats.TotalAlloc))
	runtimeMemStats.Sys.Set(float64(memStats.Sys))
	runtimeMemStats.HeapAlloc.Set(float64(memStats.HeapAlloc))

	// 注册自定义 collector
	collector := &ProxyStatusCollector{pstatus: pstatus}
	registry.MustRegister(collector)

	promhttp.Handler().ServeHTTP(w, r)
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)

}

type statConf struct {
	Verbose      bool     `json:"verbose"`
	LogFlags     int      `json:"logflag"`
	TCPBufSize   int      `json:"tcpbufsize"`
	UDPBufSize   int      `json:"udpbufsize"`
	RateLimit    int64    `json:"ratelimit"`
	Listens      []string `json:"listens"`
	StatusServer string   `json:"statserver"`
	Forwards     []string `json:"forwards"`
	RuleFiles    []string `json:"rulefiles"`
	RulesDir     string   `json:"rulesdir"`
	DNS          string   `json:"dns"`
	Services     []string `json:"services"`
}

func handler3(w http.ResponseWriter, r *http.Request, c *Config, user, pass string, acl []string) {

	ip := r.RemoteAddr
	isAllowed, err := IsIPInSubnets(ip, acl)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !isAllowed {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		log.Printf("[main] StatusServer: Unauthorized from %s", r.RemoteAddr)
		return
	}

	if user != "" {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 验证用户名和密码
		if username != user || password != pass {
			http.Error(w, "Unauthorized for "+username+":"+password, http.StatusUnauthorized)
			return
		}
	}

	sconf := statConf{
		Verbose:      c.Verbose,
		LogFlags:     c.LogFlags,
		TCPBufSize:   c.TCPBufSize,
		UDPBufSize:   c.UDPBufSize,
		RateLimit:    c.RateLimit,
		Listens:      c.Listens,
		StatusServer: c.StatusServer,
		Forwards:     c.Forwards,
		RuleFiles:    c.RuleFiles,
		RulesDir:     c.RulesDir,
		DNS:          c.DNS,
		Services:     c.Services,
	}

	// 设置响应头为JSON格式
	w.Header().Set("Content-Type", "application/json")

	// 将结构体数组编码为JSON并写入响应
	if err := json.NewEncoder(w).Encode(sconf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handler2(w http.ResponseWriter, r *http.Request, pxy *rule.Proxy, user, pass string, acl []string) {
	ip := r.RemoteAddr
	isAllowed, err := IsIPInSubnets(ip, acl)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !isAllowed {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		log.Printf("[main] StatusServer: Unauthorized from %s", r.RemoteAddr)
		return
	}

	query := r.URL.Query()
	op := query.Get("op")
	url := query.Get("url")
	enabled := query.Get("enabled")
	index, err := strconv.Atoi(query.Get("id"))
	if err != nil {
		index = 0
	}
	prio, err1 := strconv.Atoi(query.Get("priority"))
	if err1 != nil {
		prio = -1
	}

	if user != "" {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 验证用户名和密码
		if username != user || password != pass {
			http.Error(w, "Unauthorized for "+username+":"+password, http.StatusUnauthorized)
			return
		}
	}

	// 根据参数值进行不同的响应
	if op == "" {
		http.Error(w, "no operation", http.StatusTeapot)
		return
	}
	switch op {
	case "enable", "disable":
		// 设置响应头为JSON格式
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// 创建要返回的JSON数据
		pstatus := pxy.OperateMain(uint32(index), url, enabled, prio, op, "")

		// 将结构体数组编码为JSON并写入响应
		if err := json.NewEncoder(w).Encode(pstatus); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "check":
		pxy.SetCheckNow(uint32(index), url, enabled, prio)
		// 设置响应头为JSON格式
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// 创建要返回的JSON数据
		pstatus := pxy.GetMainStatus(uint32(index), url, "", prio)
		// 将结构体数组编码为JSON并写入响应
		if err := json.NewEncoder(w).Encode(pstatus); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "setpriority":
		stat := query.Get("priority")
		_, err = strconv.Atoi(stat)
		if err != nil {
			stat = "100"
		}
		if prio == -1 {
			prio = 100
		}

		pstatus := pxy.OperateMain(uint32(index), url, enabled, -1, op, strconv.Itoa(prio))

		// 设置响应头为JSON格式
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// 将结构体数组编码为JSON并写入响应
		if err := json.NewEncoder(w).Encode(pstatus); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	default:
	}

}
