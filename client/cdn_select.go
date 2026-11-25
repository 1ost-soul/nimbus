package main

import (
	"crypto/tls"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

// defaultCDNCandidateIPs 是常见 CDN 任播入口的示例集合。
// 实际部署时建议用 cdn_candidate_ips 覆盖为当前服务商推荐的入口列表。
var defaultCDNCandidateIPs = []string{
	"1.1.1.1",
	"1.0.0.1",
	"104.16.0.1",
	"104.17.0.1",
	"104.18.0.1",
	"172.64.0.1",
	"162.158.0.1",
	"198.41.128.1",
	"188.114.96.1",
	"188.114.97.1",
}

type cdnResult struct {
	addr string
	rtt  time.Duration
}

// selectCDNCandidates 并发探测候选入口，只按 TLS 握手耗时排序。
// 结果只保存在进程内存中，不写入配置或日志中的具体地址。
func selectCDNCandidates(sni, port string, candidates []string, cfg *tls.Config) []string {
	if len(candidates) == 0 {
		candidates = defaultCDNCandidateIPs
	}
	results := make(chan cdnResult, len(candidates))
	var wg sync.WaitGroup
	for _, ip := range candidates {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			start := time.Now()
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", net.JoinHostPort(ip, port), cfg)
			if err != nil {
				return
			}
			_ = conn.Close()
			results <- cdnResult{addr: net.JoinHostPort(ip, port), rtt: time.Since(start)}
		}(ip)
	}
	wg.Wait()
	close(results)

	var rs []cdnResult
	for r := range results {
		rs = append(rs, r)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].rtt < rs[j].rtt })
	addrs := make([]string, 0, len(rs))
	for _, r := range rs {
		addrs = append(addrs, r.addr)
	}
	if len(addrs) > 0 {
		log.Printf("cdn candidate selection: ok=%d best_rtt=%s", len(addrs), rs[0].rtt.Round(time.Millisecond))
	} else {
		log.Printf("cdn candidate selection: ok=0; using system dns")
	}
	return addrs
}
