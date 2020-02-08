package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"

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
var ranger = cidranger.NewPCTrieRanger()

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

func rangeAws() {
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
func rangeFlare(url string) {
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		ipcidr := scanner.Text()
		reverseMap[ipcidr] = "Cloudflare"
		_, network, _ := net.ParseCIDR(ipcidr)
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

var domainRegexp = regexp.MustCompile(`include:([^\s]+)`)
var ipRegexp = regexp.MustCompile(`ip\d:([^\s]+)`)

func rangeGoogle() {
	r, err := net.LookupTXT("_cloud-netblocks.googleusercontent.com")
	if err != nil {
		panic(err)
	}
	for _, e := range r {
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
					reverseMap[ipSubMatches[1]] = "Google"
					ranger.Insert(cidranger.NewBasicRangerEntry(*net))
				}
			}

		}
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
	rangeAws()
	rangeFlare("https://www.cloudflare.com/ips-v6")
	rangeFlare("https://www.cloudflare.com/ips-v4")
	rangeGoogle()
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
