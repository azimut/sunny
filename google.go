package main

import (
	"net"
	"regexp"
	"sync"

	"github.com/yl2chen/cidranger"
)

func rangeGoogle(mutex *sync.Mutex, wg *sync.WaitGroup) {

	record, err := net.LookupTXT("_cloud-netblocks.googleusercontent.com")
	if err != nil {
		panic(err)
	}

	var domainRegexp = regexp.MustCompile(`include:([^\s]+)`)
	var ipRegexp = regexp.MustCompile(`ip\d:([^\s]+)`)

	for _, e := range record {
		matches := domainRegexp.FindAllStringSubmatch(e, -1)
		for _, subMatches := range matches {
			r, err := net.LookupTXT(subMatches[1])
			if err != nil {
				panic(err)
			}
			for _, e := range r {
				ipMatches := ipRegexp.FindAllStringSubmatch(e, -1)

				for _, ipSubMatches := range ipMatches {
					_, net, err := net.ParseCIDR(ipSubMatches[1])
					if err != nil {
						panic(err)
					}
					mutex.Lock()
					reverseMap[ipSubMatches[1]] = "Google"
					mutex.Unlock()
					ranger.Insert(cidranger.NewBasicRangerEntry(*net))
				}
			}

		}
	}
	wg.Done()
}
