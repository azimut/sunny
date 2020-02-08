package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/yl2chen/cidranger"
)

type AWSRanges struct {
	Prefixes     []Prefix     `json:"prefixes"`
	IPv6Prefixes []IPv6Prefix `json:"ipv6_prefixes"`
}

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

var awsRanges *AWSRanges
var ipV4AWSRangesIPNets []*net.IPNet
var ipV6AWSRangesIPNets []*net.IPNet

var reverseMap map[string]string

func loadAWSRanges() *AWSRanges {
	file, err := ioutil.ReadFile("/home/sendai/ip-ranges.json")
	if err != nil {
		panic(err)
	}
	var ranges AWSRanges
	err = json.Unmarshal(file, &ranges)
	if err != nil {
		panic(err)
	}
	return &ranges
}

func rangeAws(ranger cidranger.Ranger) {
	for _, prefix := range awsRanges.Prefixes {
		reverseMap[prefix.IPPrefix] = prefix.Service
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}
	for _, prefix := range awsRanges.IPv6Prefixes {
		reverseMap[prefix.IPPrefix] = prefix.Service
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}
}

func main() {
	reverseMap = make(map[string]string)
	info, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}

	if info.Mode()&os.ModeCharDevice != 0 || info.Size() <= 0 {
		fmt.Println("The command is intended to run ONLY through pipes")
		fmt.Println("Usage: sunny < ips.txt")
		return
	}

	scanner := bufio.NewScanner(os.Stdin)
	var output []string
	for scanner.Scan() {
		output = append(output, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Println(err)
		return
	}
	//
	awsRanges = loadAWSRanges()
	ranger := cidranger.NewPCTrieRanger()
	rangeAws(ranger)
	//
	for _, iptemp := range output {
		contains, err := ranger.ContainingNetworks(net.ParseIP(iptemp))
		if err != nil {
			fmt.Println("err")
			return
		}

		if len(contains) == 0 {
			fmt.Println(iptemp)
		} else {
			for _, network := range contains {
				connected := network.Network()
				fmt.Printf("%s,%s,%s\n",
					iptemp,
					connected.String(),
					reverseMap[connected.String()])
				break
			}
		}
	}
}
