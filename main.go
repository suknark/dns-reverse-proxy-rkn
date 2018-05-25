/*
Binary dns_reverse_proxy is a DNS reverse proxy to route queries to DNS servers.
To illustrate, imagine an HTTP reverse proxy but for DNS.
It listens on both TCP/UDP IPv4/IPv6 on specified port.
Since the upstream servers will not see the real client IPs but the proxy,
you can specify a list of IPs allowed to transfer (AXFR/IXFR).
Example usage:
        $ go run dns_reverse_proxy.go -address :53 \
                -default 8.8.8.8:53 \
                -route .example.com.=8.8.4.4:53 \
                -allow-transfer 1.2.3.4,::1
A query for example.net or example.com will go to 8.8.8.8:53, the default.
However, a query for subdomain.example.com will go to 8.8.4.4:53.
*/
package main

import (
	"flag"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"sort"
)

var (
	address = flag.String("address", ":53", "Address to listen to (TCP and UDP)")

	defaultServer = flag.String("default", "",
		"Default DNS server where to send queries if no route matched (host:port)")

	routeList = flag.String("route", "",
		"List of routes where to send queries (domain=host:port)")
	routes map[string]string

	allowTransfer = flag.String("allow-transfer", "",
		"List of IPs allowed to transfer (AXFR/IXFR)")
	transferIPs []string
)

func main() {
	flag.Parse()
	if !validHostPort(*defaultServer) {
		log.Fatal("-default is required, must be valid host:port")
	}
	var subnets []string
	transferIPs = strings.Split(*allowTransfer, ",")
	routes = make(map[string]string)
	if *routeList != "" {
		for _, s := range strings.Split(*routeList, ",") {
			s := strings.SplitN(s, "=", 2)
			if len(s) != 2 || !validHostPort(s[1]) {
				log.Fatal("invalid -route, must be list of domain=host:port")
			}
			if !strings.HasSuffix(s[0], ".") {
				s[0] += "."
			}
			routes[s[0]] = s[1]
		}
	}
	go func() {
		for {
			log.Println("Download block list")
			subnets = DownloadBlockedList()
			log.Println("Done")
			log.Println("Subnets count:", len(subnets))
			time.Sleep(3 * time.Hour)
		}
	}()
	udpServer := &dns.Server{Addr: *address, Net: "udp"}
	tcpServer := &dns.Server{Addr: *address, Net: "tcp"}
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) { route(w, r, subnets) })
	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// Wait for SIGINT or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	udpServer.Shutdown()
	tcpServer.Shutdown()
}

func validHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return false
	}
	return true
}

func route(w dns.ResponseWriter, req *dns.Msg, subnets []string) {
	if len(req.Question) == 0 || !allowed(w, req) {
		dns.HandleFailed(w, req)
		return
	}
	for name, addr := range routes {
		if strings.HasSuffix(req.Question[0].Name, name) {
			proxy(addr, w, req, subnets)
			return
		}
	}
	proxy(*defaultServer, w, req, subnets)
}

func isTransfer(req *dns.Msg) bool {
	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeIXFR, dns.TypeAXFR:
			return true
		}
	}
	return false
}

func allowed(w dns.ResponseWriter, req *dns.Msg) bool {
	if !isTransfer(req) {
		return true
	}
	remote, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	for _, ip := range transferIPs {
		if ip == remote {
			return true
		}
	}
	return false
}

func proxy(addr string, w dns.ResponseWriter, req *dns.Msg, subnets []string) {
	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	if isTransfer(req) {
		if transport != "tcp" {
			dns.HandleFailed(w, req)
			return
		}
		t := new(dns.Transfer)
		c, err := t.In(req, addr)
		if err != nil {
			dns.HandleFailed(w, req)
			return
		}
		if err = t.Out(w, req, c); err != nil {
			dns.HandleFailed(w, req)
			return
		}
		return
	}
	c := &dns.Client{Net: transport}
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}
	var v []dns.RR
	for _, i := range resp.Answer {
		for _, b := range strings.Split(i.String(), "\n") {
			ip := strings.Split(b, "\t")
			if CIDRMatch(subnets, ip[len(ip)-1]) {
				v = append(v, i)
			} else {
				log.Println("Blocked ip ", ip[len(ip)-1])
				continue
			}
		}
	}
	//fmt.Println(v)
	tt := &dns.Msg{
		MsgHdr:   resp.MsgHdr,
		Compress: resp.Compress,
		Question: resp.Question,
		Answer:   v,
		Ns:       resp.Ns,
		Extra:    resp.Extra,
	}
	w.WriteMsg(tt)
}

func DownloadBlockedList() (nets []string) {
	var networks []string
	resp, err := http.Get("https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	a := strings.Split(string(b), "\n")
	for _, bla := range a {
		nn := strings.Split(strings.Split(bla, ";")[0], "|")
		for _, net := range nn {
			if len(net) > 0 {
				if strings.Index(net, "/") != -1 {
					networks = append(networks, strings.Replace(net, " ", "", -1))
				} else {
					networks = append(networks, strings.Replace(net, " ", "", -1)+"/32")
				}
			}
		}
	}
	encountered := map[string]bool{}
	result := []string{}

	for v := range networks {
		if encountered[networks[v]] == true {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[networks[v]] = true
			// Append to result slice.
			result = append(result, networks[v])
		}
	}
	sort.Strings(result)
	return result
}

func CIDRMatch(nets []string, ne string) bool {
	for i := len(nets)-1; i >= 0; i-- {
		if strings.Index(nets[i], "Updated") != -1 {
			continue
		}
		_, cidrnet, err := net.ParseCIDR(nets[i])
		if err != nil {
			log.Println(err) // assuming I did it right above
		}
		myaddr := net.ParseIP(ne)
		if cidrnet.Contains(myaddr) {
			return false
			break
		} else {
			continue
		}
	}
	return true
}
