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


// 启动HTTP服务器的函数，接收一个Config指针
func startServer(p *rule.Proxy, addr string) {
	// 定义HTTP处理函数
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		handler1(w, r, p)
	})
	http.HandleFunc("/operation", func(w http.ResponseWriter, r *http.Request) {
		handler2(w, r, p)
	})

	// 启动HTTP服务器
	fmt.Printf("Status Server is listening on %s...\n", addr)
	//log.F("Status Server is listening on %s...\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}

// 处理HTTP请求的函数

func handler1(w http.ResponseWriter, r *http.Request,pxy *rule.Proxy) {
	// 设置响应头为JSON格式
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	pstatus:=[]rule.ProxyStatus{}
	index:=0
	//fmt.Printf("API : %v",r.URL)
	query := r.URL.Query()
	id := query.Get("id") 
	enabled := query.Get("enabled") 
	index,err:=strconv.Atoi(id)
	if err!=nil {
		index=0
	}
	// 创建要返回的JSON数据
	if enabled!="" {
		
		if enabled=="1" {
			pstatus=pxy.GetMainEnabled(true)
		} else {
			pstatus=pxy.GetMainEnabled(false)
		}
	} else {
		pstatus=pxy.GetMainStatus(uint32(index))
		
	}
	// 将结构体数组编码为JSON并写入响应
	if err := json.NewEncoder(w).Encode(pstatus); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}



func handler2(w http.ResponseWriter, r *http.Request,pxy *rule.Proxy) {
		//fmt.Printf("API : %v",r.URL)
	query := r.URL.Query()
	op := query.Get("op")  
	id := query.Get("id") 
	

	// 根据参数值进行不同的响应
	if op == "" {
		fmt.Fprintf(w, "no operation")
		return
	}
	switch op {
		case "enable", "disable":
			index,err:=strconv.Atoi(id)
			if err!=nil {
				fmt.Fprintf(w, "invalid id")
				return
			}
			pxy.OperateMainbyID(uint32(index),op)
			// 设置响应头为JSON格式
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")

			// 创建要返回的JSON数据
			pstatus:=pxy.GetMainStatus(uint32(index))
			// 将结构体数组编码为JSON并写入响应
			if err := json.NewEncoder(w).Encode(pstatus); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case "check":
			index,err:=strconv.Atoi(id)
			if err!=nil {
				fmt.Fprintf(w, "invalid id")
				return
			}
			pxy.SetCheckNow(uint32(index))
			// 设置响应头为JSON格式
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")

			// 创建要返回的JSON数据
			pstatus:=pxy.GetMainStatus(uint32(index))
			// 将结构体数组编码为JSON并写入响应
			if err := json.NewEncoder(w).Encode(pstatus); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		default:
	}

}
