package main

import (
	"bufio"
	"net"
	"net/http"
	"sync"

	"github.com/yl2chen/cidranger"
)

func rangeRawHttp(url string, provider string, mutex *sync.Mutex, wg *sync.WaitGroup) {
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		ipcidr := scanner.Text()
		mutex.Lock()
		reverseMap[ipcidr] = provider
		mutex.Unlock()
		_, network, _ := net.ParseCIDR(ipcidr)
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	wg.Done()
}
