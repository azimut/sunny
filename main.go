package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/ammario/ipisp"
	"github.com/yl2chen/cidranger"
)

var reverseMap map[string]string
var ranger = cidranger.NewPCTrieRanger()

func main() {
	var wg sync.WaitGroup
	var mutex sync.Mutex

	var ips []string
	var cloudless []net.IP
	reverseMap = make(map[string]string)

	// Force STDIN only
	info, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		fmt.Println("The command is intended to run ONLY through pipes")
		fmt.Println("Usage: cat ips.txt | sunny")
		return
	}

	// Add STDIN to ips (no validation)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		ips = append(ips, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	wg.Add(7)
	go rangeRawHttp("https://www.cloudflare.com/ips-v6", "Cloudflare", &mutex, &wg)
	go rangeRawHttp("https://www.cloudflare.com/ips-v4", "Cloudflare", &mutex, &wg)
	go rangeRawHttp("https://raw.githubusercontent.com/SecOps-Institute/Akamai-ASN-and-IPs-List/master/akamai_ip_cidr_blocks.lst", "Akamai", &mutex, &wg)
	go rangeAws(&mutex, &wg)
	go rangeMicrosoft(&mutex, &wg)
	go rangeGoogle(&mutex, &wg)
	go rangeLocal(&mutex, &wg)
	wg.Wait()

	// Process INPUT ips with resolved data
	for _, ip := range ips {
		contains, err := ranger.ContainingNetworks(net.ParseIP(ip))
		if err != nil {
			fmt.Println("failed while parsing IP into a CIDR")
			return
		}
		if len(contains) == 0 {
			cloudless = append(cloudless, net.ParseIP(ip))
		} else {
			for _, network := range contains {
				connected := network.Network()
				fmt.Printf("%s,%s,\"%s\"\n",
					ip,
					connected.String(),
					reverseMap[connected.String()])
				break
			}
		}
	}

	// Fallback to WHOIS, for cloudless IPs
	client, err := ipisp.NewWhoisClient()
	if err != nil {
		panic(err)
	}
	defer client.Close()
	responses, err := client.LookupIPs(cloudless)
	if err != nil {
		panic(err)
	}
	for _, resp := range responses {
		fmt.Printf("%s,%s,\"%s\"\n",
			resp.IP,
			resp.Range,
			resp.Name.Long)
	}
}
