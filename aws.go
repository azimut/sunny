package main

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"sync"

	"github.com/yl2chen/cidranger"
)

type Prefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

type IPv6Prefix struct {
	IPPrefix string `json:"ipv6_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

type AWSRanges struct {
	Prefixes     []Prefix     `json:"prefixes"`
	IPv6Prefixes []IPv6Prefix `json:"ipv6_prefixes"`
}

func rangeAws(mutex *sync.Mutex, wg *sync.WaitGroup) {

	url := "https://ip-ranges.amazonaws.com/ip-ranges.json"
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	var awsRanges *AWSRanges
	err = json.Unmarshal(body, &awsRanges)
	if err != nil {
		panic(err)
	}

	for _, prefix := range awsRanges.Prefixes {
		mutex.Lock()
		reverseMap[prefix.IPPrefix] = prefix.Service
		mutex.Unlock()
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}
	for _, prefix := range awsRanges.IPv6Prefixes {
		mutex.Lock()
		reverseMap[prefix.IPPrefix] = prefix.Service
		mutex.Unlock()
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}
	wg.Done()
}
