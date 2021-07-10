package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type Config struct {
	APPID     string
	SecretId  string
	SecretKey string
	Domain    string
	SubDomain string
}

type RawRequestParam map[string]interface{}

type DNSRecord struct {
	Id    int
	Type  string
	Value string
	Name  string
	Line  string
}

type RecordListResponse struct {
	Code     int
	CodeDesc string
	Message  string
	Data     struct {
		Records []DNSRecord
	}
}

type RecordModifyResponse struct {
	Code     int
	CodeDesc string
	Message  string
	Data     struct {
		Record struct {
			Id     int
			Name   string
			Value  string
			Status string
			Weight string
		}
	}
}

func (p RawRequestParam) appendTo(buf *bytes.Buffer) {
	keys := make([]string, 0, len(p))
	for key := range p {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(fmt.Sprint(p[k]))
		buf.WriteString("&")
	}
	buf.Truncate(buf.Len() - 1)
}

var defaultTransport http.RoundTripper = &http.Transport{
	Proxy: nil,
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	MaxIdleConns:          30,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   15 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}
var client = &http.Client{Transport: defaultTransport}

func main() {
	// prepare logger
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	logfile, err := os.OpenFile("dns-to-me.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.WithField("error", err).Fatalf("Log file unavailable.")
	}
	defer logfile.Close()
	log.SetOutput(io.MultiWriter(os.Stdout, logfile))

	// main loop
	{
		log.Infof("====== New Loop ======")
		config := readConfig()
		wanIp := getPublicIp()
		wanIpv6 := getPublicIpv6()
		updateDns(wanIp, config, false)
		updateDns(wanIpv6, config, true)
		time.Sleep(10 * time.Second)
	}
}

func updateDns(ip string, config Config, isV6 bool) {
	if ip == "" {
		log.Errorf("TARGET IP INCORRECT.")
		return
	}
	// get existing records
	requestMethod := http.MethodGet
	requestURI := "cns.api.qcloud.com/v2/index.php"
	requestParam1 := createNewParam(config)
	requestParam1["Action"] = "RecordList"
	requestParam1["domain"] = config.Domain
	log.WithField("requestParam1", requestParam1).Infof("Raw param")
	requestParam1["Signature"] = signWithHmacSHA1(requestMethod, requestURI, requestParam1, config)
	req1, _ := http.NewRequest(requestMethod, "https://"+requestURI, nil)
	q1 := req1.URL.Query()
	for paramKey, paramValue := range requestParam1 {
		q1.Add(paramKey, fmt.Sprint(paramValue))
	}
	req1.URL.RawQuery = q1.Encode()
	log.WithFields(log.Fields{"url": req1.URL.String()}).Infof("Request")
	resp1, err1 := client.Do(req1)
	if err1 != nil || resp1.StatusCode != http.StatusOK {
		log.WithFields(log.Fields{"resp1": resp1, "err1": err1}).Errorf("Request error")
		return
	}
	body1, _ := ioutil.ReadAll(resp1.Body)
	rl := RecordListResponse{}
	_ = json.Unmarshal(body1, &rl)
	defer resp1.Body.Close()
	log.WithFields(log.Fields{"body1": rl}).Debugf("Request done")
	var toModRecord DNSRecord
	for _, dnsRecord := range rl.Data.Records {
		if !isV6 && dnsRecord.Type == "A" && dnsRecord.Name == config.SubDomain {
			toModRecord = dnsRecord
			break
		} else if isV6 && dnsRecord.Type == "AAAA" && dnsRecord.Name == config.SubDomain {
			toModRecord = dnsRecord
			break
		}
	}
	log.WithFields(log.Fields{"ipBefore": toModRecord}).Infof("Existing IP")
	if toModRecord.Value == "" {
		log.Errorf("OLD IP INCORRECT.")
		return
	}
	// start modify
	if toModRecord.Value == ip {
		log.Infof("IP NOT CHANGED.")
		return
	}
	requestParam2 := createNewParam(config)
	requestParam2["Action"] = "RecordModify"
	requestParam2["domain"] = config.Domain
	requestParam2["recordId"] = toModRecord.Id
	requestParam2["subDomain"] = toModRecord.Name
	requestParam2["recordType"] = toModRecord.Type
	requestParam2["recordLine"] = toModRecord.Line
	requestParam2["value"] = ip
	log.WithField("requestParam2", requestParam2).Infof("Raw param")
	requestParam2["Signature"] = signWithHmacSHA1(requestMethod, requestURI, requestParam2, config)
	req2, _ := http.NewRequest(requestMethod, "https://"+requestURI, nil)
	q2 := req2.URL.Query()
	for paramKey, paramValue := range requestParam2 {
		q2.Add(paramKey, fmt.Sprint(paramValue))
	}
	req2.URL.RawQuery = q2.Encode()
	log.WithFields(log.Fields{"url": req2.URL.String()}).Infof("Request")
	resp2, err2 := client.Do(req2)
	if err2 != nil || resp2.StatusCode != http.StatusOK {
		log.WithFields(log.Fields{"resp2": resp2, "err2": err2}).Errorf("Request error")
		return
	}
	body2, _ := ioutil.ReadAll(resp2.Body)
	rm := RecordModifyResponse{}
	err2 = json.Unmarshal(body2, &rm)
	defer resp2.Body.Close()
	log.WithFields(log.Fields{"body2": rm}).Infof("Modify done")
}

func signWithHmacSHA1(requestMethod string, requestURI string, requestParam RawRequestParam, config Config) string {
	var buf bytes.Buffer
	buf.WriteString(requestMethod)
	buf.WriteString(requestURI)
	buf.WriteString("?")
	requestParam.appendTo(&buf)
	hashed := hmac.New(sha1.New, []byte(config.SecretKey))
	hashed.Write(buf.Bytes())
	signature := base64.StdEncoding.EncodeToString(hashed.Sum(nil))
	log.WithFields(log.Fields{"message": buf.String(), "signature": signature}).Infof("Signed")
	return signature
}

func createNewParam(config Config) RawRequestParam {
	rawParam := RawRequestParam{}
	rawParam["Timestamp"] = time.Now().Unix()
	rand.Seed(time.Now().UnixNano())
	rawParam["Nonce"] = rand.Uint32()
	rawParam["SecretId"] = config.SecretId
	rawParam["SignatureMethod"] = "HmacSHA1"
	return rawParam
}

func getPublicIp() string {
	resp, err := client.Get("http://ip-api.com/line/?fields=query")
	if err != nil {
		log.WithError(err).Fatalf("Request WAN IP failed")
		return ""
	}
	defer resp.Body.Close()
	doc, err := ioutil.ReadAll(resp.Body)
	wanIp := strings.TrimSpace(fmt.Sprintf("%s", doc))
	log.WithFields(log.Fields{
		"statusCode": resp.StatusCode,
		"wanIp":      wanIp,
	}).Infof("Got the WAN IP")
	return wanIp
}

func getPublicIpv6() string {
	resp, err := client.Get("http://v6.ipv6-test.com/api/myip.php")
	if err != nil {
		log.WithError(err).Fatalf("Request WAN IP failed")
		return ""
	}
	defer resp.Body.Close()
	doc, err := ioutil.ReadAll(resp.Body)
	wanIpv6 := strings.TrimSpace(fmt.Sprintf("%s", doc))
	log.WithFields(log.Fields{
		"statusCode": resp.StatusCode,
		"wanIpv6":    wanIpv6,
	}).Infof("Got the WAN IPv6")
	return wanIpv6
}

func readConfig() (result Config) {
	file, err := os.Open("dns-to-me-config.json")
	if err != nil {
		log.WithField("error", err).Fatalf("Settings unavailable")
	}
	defer file.Close()
	byteVal, _ := ioutil.ReadAll(file)
	err = json.Unmarshal(byteVal, &result)
	if err != nil {
		log.WithField("error", err).Errorf("Unmarshal error")
	}
	log.Infof("Settings loaded")
	return
}
