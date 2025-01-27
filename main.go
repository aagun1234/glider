package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"net/http"
	"fmt"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/nadoo/glider/dns"
	"github.com/nadoo/glider/ipset"
	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/rule"
	"github.com/nadoo/glider/service"
)

var (
	version = "0.17.0"
	config = parseConfig()
)

func main() {
	// global rule proxy
	pxy := rule.NewProxy(config.Forwards, &config.Strategy, config.rules)

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
	if config.StatusServer!="" {
		go startServer(pxy,config.StatusServer)
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

func startServer(p *rule.Proxy, addr string) {

	saddr :=addr
	auser:=""
	apass:=""

    if strings.Contains(addr,"@") {
		server1 := strings.Split(addr, "@")
		saddr = server1[1]

		if strings.Contains(server1[0],":") {
			auth1 := strings.Split(server1[0], ":")
			auser=auth1[0]
			apass=auth1[1]
		} else {
			auser=server1[0]
			apass=""
		}
	}

	// 定义HTTP处理函数
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		handler1(w, r, p,auser,apass)
	})
	http.HandleFunc("/operation", func(w http.ResponseWriter, r *http.Request) {
		handler2(w, r, p,auser,apass)
	})

	// 启动HTTP服务器
	fmt.Printf("Status Server is listening on %s...\n", saddr)
	//log.F("Status Server is listening on %s...\n", addr)
	if err := http.ListenAndServe(saddr, nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}

// 处理HTTP请求的函数
func handler1(w http.ResponseWriter, r *http.Request,pxy *rule.Proxy, user,pass string) {
	pstatus:=[]rule.ProxyStatus{}
	index:=0
	//fmt.Printf("API : %v",r.URL)
	query := r.URL.Query()
	enabled := query.Get("enabled") 
	available := query.Get("available") 
	url := query.Get("url")
	
	index,err:=strconv.Atoi(query.Get("id"))
	if err!=nil {
		index=0
	}
	prio,err1:=strconv.Atoi(query.Get("priority"))
	if err1!=nil {
		prio=-1
	}
	
	if user!="" {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 验证用户名和密码
		if username !=user || password!=pass {
			http.Error(w, "Unauthorized for "+username+":"+password, http.StatusUnauthorized)
			return
		}
	}	
	
		// 设置响应头为JSON格式
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 创建要返回的JSON数据
	if available=="1" || available=="true" {
		pstatus=pxy.GetAvailStatus(uint32(index),url,enabled,prio)
	} else {
		pstatus=pxy.GetMainStatus(uint32(index),url,enabled,prio)
	}
	// 将结构体数组编码为JSON并写入响应
	if err := json.NewEncoder(w).Encode(pstatus); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}



func handler2(w http.ResponseWriter, r *http.Request,pxy *rule.Proxy, user,pass string) {
		//fmt.Printf("API : %v",r.URL)
	query := r.URL.Query()
	op := query.Get("op")  
	url := query.Get("url")
	enabled := query.Get("enabled") 
	index,err:=strconv.Atoi(query.Get("id"))
	if err!=nil {
		index=0
	}
	prio,err1:=strconv.Atoi(query.Get("priority"))
	if err1!=nil {
		prio=-1
	}
	
	if user!="" {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 验证用户名和密码
		if username !=user || password!=pass {
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
			pstatus:=pxy.OperateMain(uint32(index), url, enabled, prio, op, "")

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
			pstatus:=pxy.GetMainStatus(uint32(index),url,"",prio)
			// 将结构体数组编码为JSON并写入响应
			if err := json.NewEncoder(w).Encode(pstatus); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case "setpriority":
			stat := query.Get("priority") 
			_,err=strconv.Atoi(stat)
			if err!=nil {
				stat="100"
			}
			if prio==-1 {
				prio=100
			}

			pstatus:=pxy.OperateMain(uint32(index), url, enabled, -1, op, strconv.Itoa(prio))

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
