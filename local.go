package main

import (
	"net"
	"sync"

	"github.com/yl2chen/cidranger"
)

// https://en.wikipedia.org/wiki/Reserved_IP_addresses
func rangeLocal(mutex *sync.Mutex, wg *sync.WaitGroup) {
	inets := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"}
	for _, cidr := range inets {
		_, net, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		mutex.Lock()
		reverseMap[cidr] = "LOCAL"
		mutex.Unlock()
		ranger.Insert(cidranger.NewBasicRangerEntry(*net))
	}
	wg.Done()
}
