package main

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"sync"

	"github.com/yl2chen/cidranger"
	"golang.org/x/net/html"
)

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

var azureJsonFileRegexp = regexp.MustCompile(`.*?ServiceTags.*?json`)

func rangeMicrosoft(mutex *sync.Mutex, wg *sync.WaitGroup) {
	url := "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
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
			mutex.Lock()
			reverseMap[prefix] = val.Name
			mutex.Unlock()
			ranger.Insert(cidranger.NewBasicRangerEntry(*net))
		}
	}
	wg.Done()
}
