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
	"golang.org/x/net/html"
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

type AzureMain struct {
	ChangeNumber int          `json:"changeNumber"`
	Cloud        string       `json:"cloud"`
	Values       []AzureValue `json:"values"`
}

type AzureValue struct {
	Name       string          `json:"name"`
	Id         string          `json:"id"`
	Properties AzureProperties `json:"properties"`
}

type AzureProperties struct {
	ChangeNumber    int      `json:"changeNumber"`
	Region          string   `json:"region"`
	Platform        string   `json:"platform"`
	SystemService   string   `json:"systemService"`
	AddressPrefixes []string `json:"addressPrefixes"`
}

var awsRanges *AWSRanges
var ipV4AWSRangesIPNets []*net.IPNet
var ipV6AWSRangesIPNets []*net.IPNet

var reverseMap map[string]string
var ranger = cidranger.NewPCTrieRanger()

func loadAWSRanges() *AWSRanges {
	url := "https://ip-ranges.amazonaws.com/ip-ranges.json"

	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err.Error())
	}

	var ranges AWSRanges

	err = json.Unmarshal(body, &ranges)
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
func rangeRawHttp(url string, provider string) {
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		ipcidr := scanner.Text()
		reverseMap[ipcidr] = provider
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

var azureJsonFileRegexp = regexp.MustCompile(`.*?ServiceTags.*?json`)

// url: https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653
func rangeMicrosoft(url string) {
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	jsonURI := ""
	doc := html.NewTokenizer(res.Body)
	for {
		e := doc.Next()
		if e == html.StartTagToken {
			tag := doc.Token()
			if tag.Data == "a" {
				for _, a := range tag.Attr {
					if a.Key == "href" {
						if azureJsonFileRegexp.Match([]byte(a.Val)) {
							jsonURI = a.Val
						}
						break
					}
				}
			}
		}

		if jsonURI != "" {
			break
		}
	}
	// Download Json
	req, err := http.NewRequest("GET", jsonURI, nil)
	if err != nil {
		panic(err)
	}
	for _, cookie := range res.Cookies() {
		req.AddCookie(cookie)
	}

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	var azure AzureMain
	if err := json.Unmarshal(body, &azure); err != nil {
		panic(err)
	}

	for _, val := range azure.Values {
		prop := val.Properties
		for _, prefix := range prop.AddressPrefixes {
			_, net, err := net.ParseCIDR(prefix)
			if err != nil {
				panic(err)
			}
			reverseMap[prefix] = val.Name
			ranger.Insert(cidranger.NewBasicRangerEntry(*net))
		}
	}
}
func main() {
	reverseMap = make(map[string]string)
	info, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}

	if info.Mode()&os.ModeNamedPipe == 0 {
		fmt.Println("The command is intended to run ONLY through pipes")
		fmt.Println("Usage: cat ips.txt | sunny")
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
	rangeRawHttp("https://www.cloudflare.com/ips-v6", "Cloudflare")
	rangeRawHttp("https://www.cloudflare.com/ips-v4", "Cloudflare")
	rangeRawHttp("https://raw.githubusercontent.com/SecOps-Institute/Akamai-ASN-and-IPs-List/master/akamai_ip_cidr_blocks.lst", "Akamai")
	rangeMicrosoft("https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519")
	rangeGoogle()
	//
	for _, iptemp := range output {
		contains, err := ranger.ContainingNetworks(net.ParseIP(iptemp))
		if err != nil {
			fmt.Println("err")
			return
		}
		if len(contains) == 0 {
			fmt.Printf("%s,,\n", iptemp)
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
