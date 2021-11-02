package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"github.com/cheggaaa/pb/v3"
	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
	"golang.org/x/term"

)

var JSESSIONID string
var XSRFTOKEN string
var reUseBody io.ReadCloser

var FSusername = "" //const FSusername = "user"
var FSpassword = "" //const FSpassword = "password"
var FSApplianceFQDN = "" //const FSApplianceFQDN = "appliance.forescout.local"

func removeLines(fn string, start, n int) (err error) {
	if start < 1 {
		return errors.New("invalid request.  line numbers start at 1.")
	}
	if n < 0 {
		return errors.New("invalid request.  negative number to remove.")
	}
	var f *os.File
	if f, err = os.OpenFile(fn, os.O_RDWR, 0); err != nil {
		return
	}
	defer func() {
		if cErr := f.Close(); err == nil {
			err = cErr
		}
	}()
	var b []byte
	if b, err = ioutil.ReadAll(f); err != nil {
		return
	}
	cut, ok := skip(b, start-1)
	if !ok {
		return fmt.Errorf("less than %d lines", start)
	}
	if n == 0 {
		return nil
	}
	tail, ok := skip(cut, n)
	if !ok {
		return fmt.Errorf("less than %d lines after line %d", n, start)
	}
	t := int64(len(b) - len(cut))
	if err = f.Truncate(t); err != nil {
		return
	}
	if len(tail) > 0 {
		_, err = f.WriteAt(tail, t)
	}
	return
}

func skip(b []byte, n int) ([]byte, bool) {
	for ; n > 0; n-- {
		if len(b) == 0 {
			return nil, false
		}
		x := bytes.IndexByte(b, '\n')
		if x < 0 {
			x = len(b)
		} else {
			x++
		}
		b = b[x:]
	}
	return b, true
}

func FSLogin() {
	var service *selenium.Service
	var caps selenium.Capabilities
	var wd selenium.WebDriver
	var err error
	chromedriver := "./chromedriver.exe"
	port := 9515
	chromeopts := chrome.Capabilities{
		Args: []string{
			"--headless",
			"--no-sandbox",
			"--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
		},
		ExcludeSwitches: []string{
			"enable-logging",
		},
		Path: "chrome-win\\chrome.exe",
	}
	opts := []selenium.ServiceOption{
		selenium.ChromeDriver(chromedriver), // Specify the path to GeckoDriver in order to use Firefox.
	}

	service, err = selenium.NewChromeDriverService(chromedriver, port, opts...)
	if err != nil {
		log.Fatal(err) // panic is used only as an example and is not otherwise recommended.
	}

	defer service.Stop()
	caps = selenium.Capabilities{
		"browserName":         "chrome",
		"acceptInsecureCerts": true,
	}
	caps.AddChrome(chromeopts)
	wd, err = selenium.NewRemote(caps, "http://127.0.0.1:9515/wd/hub")
	if err != nil {
		log.Printf("Error starting new remote capability: %v", err)
		log.Println(err)
	}
	defer wd.Quit()
	
	if err := wd.Get(fmt.Sprintf("https://%s/fsum/login", FSApplianceFQDN)); err != nil {
		log.Fatal(err)
	}
	username, err := wd.FindElement(selenium.ByXPATH, "//*[@id=\"username\"]")
	if err != nil {
		log.Fatal(err)
	}
	err = username.SendKeys(FSusername)
	if err != nil {
		log.Fatal(err)
	}
	password, err := wd.FindElement(selenium.ByXPATH, "//*[@id=\"password\"]")
	if err != nil {
		log.Fatal(err)
	}
	err = password.SendKeys(FSpassword)
	if err != nil {
		log.Fatal(err)
	}
	err = password.SendKeys(selenium.EnterKey)
	if err != nil {
		log.Fatal(err)
	}
	if err := wd.Get(fmt.Sprintf("https://%s/seg/singleSpaEntry.js", FSApplianceFQDN)); err != nil {
		log.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	cookies, err := wd.GetCookies()
	//fmt.Println(cookies)
	for _, cookie := range cookies {
		if cookie.Name == "JSESSIONID" {
			//fmt.Println(cookie.Name, cookie.Value)
			JSESSIONID = cookie.Value
		}
		if cookie.Name == "XSRF-TOKEN" {
			//fmt.Println(cookie.Name, cookie.Value)
			XSRFTOKEN = cookie.Value
		}
	}
}

func ConnectTest() bool {

	site := "https://forescout.scspa.local/seg/api/v1/environment/configuration"
	method := "GET"

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest(method, site, nil)

	if err != nil {
		fmt.Println(err)
		return false
	}
	req.Header.Add("Host", FSApplianceFQDN)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36")
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Set("referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return false
	}

	if len(body) == 0 {
		return false
	} else {
		return true
	}
}

func GetDSTZones(zoneID string) []string {
	var DSTZones []string
	site := fmt.Sprintf("https://%s/seg/api/v2/matrix/0/policies/visualization?srcZoneId=%s", FSApplianceFQDN, zoneID)
	method := "GET"


	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest(method, site, nil)

	if err != nil {
		fmt.Println(err)
		return nil
	}
	req.Header.Set("authority", FSApplianceFQDN)
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	req.Header.Set("referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	//fmt.Println(body)
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		panic(err)
	}
	for _, child := range jsonParsed.Children() {
		DSTZones = append(DSTZones, trimQuote(child.Path("dstZone").String()))
	}

	return DSTZones
}

func GetSRCZones(zoneID string) []string {
	var SRCZones []string
	site := fmt.Sprintf("https://%s/seg/api/v2/matrix/0/policies/visualization?dstZoneId=%s", FSApplianceFQDN, zoneID)
	method := "GET"

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest(method, site, nil)

	if err != nil {
		fmt.Println(err)
		return nil
	}
	req.Header.Set("authority", FSApplianceFQDN)
	req.Header.Set("pragma", "no-cache")
	req.Header.Set("accept", "application/json, text/plain, */*")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		panic(err)
	}
	for _, child := range jsonParsed.Children() {
		SRCZones = append(SRCZones, trimQuote(child.Path("srcZone").String()))
	}
	return SRCZones
}

func GetZoneID(zoneName string) string {
	var ZoneID string

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/seg/api/v3/environment/zone-map", FSApplianceFQDN), nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Expires", "Sat, 01 Jan 2000 00:00:00 GMT")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	req.Header.Set("TE", "Trailers")
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	jsonParsed, err := gabs.ParseJSON(bodyText)
	if err != nil {
		panic(err)
	}
	for _, zone := range jsonParsed.Path("zones").Children() {
		parsedZoneName := trimQuote(zone.Search("name").String())
		if strings.EqualFold(parsedZoneName, zoneName) {
			ZoneID = trimQuote(zone.Search("zoneId").String())
			break
		} else {
			ZoneID = "No Zone ID Found."
		}
	}
	return ZoneID
}

func trimQuote(s string) string {
	if len(s) > 0 && s[0] == '"' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == '"' {
		s = s[:len(s)-1]
	}
	return s
}

func CheckOccurrences(SRCZone string, DSTZone string) (bool, error) {
	site := fmt.Sprintf("https://%s/seg/api/v3/matrix/data/0/occurrences-by-port-range?srcZoneId=%s&dstZoneId=%s&shouldOnlyShowPolicyViolation=false", FSApplianceFQDN, SRCZone, DSTZone)
	method := "GET"

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest(method, site, nil)

	if err != nil {
		fmt.Println(err)
		return false, err
	}
	req.Header.Set("authority", FSApplianceFQDN)
	req.Header.Set("pragma", "no-cache")
	req.Header.Set("accept", "application/json, text/plain, */*")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		panic(err)
	}
	if len(jsonParsed.Children()) == 0 {
		return false, nil
	} else {
		return true, nil
	}
}

func DSTzoneToZoneConnections(SRCZone string, DSTZone string) ([]string, error) {
	var DSTZones []string
	site := fmt.Sprintf("https://%s/seg/api/v3/matrix/data/0/details/zone-traffic-details?srcZoneId=%s&dstZoneId=%s&shouldOnlyShowPolicyViolation=false&showDetailedZones=false", FSApplianceFQDN, SRCZone, DSTZone)
	method := "GET"

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest(method, site, nil)

	if err != nil {
		fmt.Println(err)
		return DSTZones, err
	}
	req.Header.Set("authority", FSApplianceFQDN)
	req.Header.Set("pragma", "no-cache")
	req.Header.Set("accept", "application/json, text/plain, */*")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return DSTZones, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return DSTZones, err
	}
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		panic(err)
	}
	for _, child := range jsonParsed.Path("zoneToZoneConnections").Children() {
		DSTZones = append(DSTZones, trimQuote(child.Path("dstZoneId").String()))
	}
	return DSTZones, nil
}

func SRCzoneToZoneConnections(SRCZone string, DSTZone string) ([]string, error) {
	var SRCZones []string
	site := fmt.Sprintf("https://%s/seg/api/v3/matrix/data/0/details/zone-traffic-details?srcZoneId=%s&dstZoneId=%s&shouldOnlyShowPolicyViolation=false&showDetailedZones=false", FSApplianceFQDN, SRCZone, DSTZone)
	method := "GET"

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest(method, site, nil)

	if err != nil {
		fmt.Println(err)
		return SRCZones, err
	}
	req.Header.Set("authority", FSApplianceFQDN)
	req.Header.Set("pragma", "no-cache")
	req.Header.Set("accept", "application/json, text/plain, */*")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return SRCZones, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return SRCZones, err
	}
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		panic(err)
	}
	for _, child := range jsonParsed.Path("zoneToZoneConnections").Children() {
		SRCZones = append(SRCZones, trimQuote(child.Path("srcZoneId").String()))
	}
	return SRCZones, nil
}

func ExportData(SRCZone string, DSTZone string) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DisableCompression: true,
	}

	client := &http.Client{
		Transport: transport,
	}


	site := fmt.Sprintf("https://%s/seg/api/v3/matrix/data/0/services-export", FSApplianceFQDN)
	method := "POST"

	//payload := strings.NewReader(`{"srcZoneId":"g_8973766297000773843","dstZoneId":"g_3554460426726078343","shouldOnlyShowPolicyViolation":false}`)
	payloadFormat := fmt.Sprintf(`{"srcZoneId":"%s","dstZoneId":"%s","shouldOnlyShowPolicyViolation":false}`, SRCZone, DSTZone)
	payload := strings.NewReader(payloadFormat)
	req, err := http.NewRequest(method, site, payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Host", FSApplianceFQDN)
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Add("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Sec-Fetch-Mode", "cors")
	req.Header.Add("Sec-Fetch-Dest", "empty")
	req.Header.Set("referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	//req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Connection", "close")
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)
	req.Header.Set("X-Xsrf-Token", XSRFTOKEN)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	if req.Body != nil {
		reUseBody, _ = req.GetBody()
	}
	if reUseBody != nil {
		req.Body = reUseBody
	}

	re := regexp.MustCompile(`"(.*?)"`)
	filename := re.FindString(strings.Join(resp.Header["Content-Disposition"], "; "))
	filename = strings.ReplaceAll(filename, "\"", "")

	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	ioutil.WriteFile(filename, bodyText, 644)
	resp.Body.Close()

	f, _ := os.Open(filename)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "Source_Zone") {
			removeLines(filename, 1, 1)
		} else {
			break
		}
	}


}

func timeBasedFilter(days int) {

	site := fmt.Sprintf("https://%s/seg/api/v1/user/configuration/timeBasedFilter", FSApplianceFQDN)
	method := "PUT"

	payload := strings.NewReader(fmt.Sprintf("{\"lastDaysFilter\":%d}", days))

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
	}
	req, err := http.NewRequest(method, site, payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Host", FSApplianceFQDN)
	req.Header.Add("X-Xsrf-Token", XSRFTOKEN)
	req.Header.Add("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Add("Origin", fmt.Sprintf("https://%s", FSApplianceFQDN))
	req.Header.Set("referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	//req.Header.Add("Accept-Encoding", "gzip, deflate")
	//req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Sprintln(string(body))
}

func StringPrompt(label string) string {
	var s string
	r := bufio.NewReader(os.Stdin)
	if label == "Password:" {
		fmt.Fprint(os.Stderr, label+" ")
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
		s = string(bytePassword)
	} else {
		for {
			fmt.Fprint(os.Stderr, label+" ")
			s, _ = r.ReadString('\n')
			if s != "" {
				break
			}
		}
	}
	return strings.TrimSpace(s)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	GetDSTZonesFlag := flag.Bool("d", false, "Get all destination zones from selected source.")
	GetSRCZonesFlag := flag.Bool("s", false, "Get all source zones from selected destination.")
	CheckZoneID := flag.Bool("c", false, "Print Zone ID from given name.")
	ZoneName := flag.String("n", "", "Specify a Zone name to lookup.")
	exportDSTDataFlag := flag.Bool("oS", false, "Export data given source name. (Requires -n)")
	exportSRCDataFlag := flag.Bool("oD", false, "Export data given destination name. (Requires -n)")
	timeFilter := flag.Int("f", 3, "Set how many days to look back into the data.")
	test := flag.Bool("t", false, "flag to test functions")
	username := flag.String("u", FSusername, "Specify username to connect to server with. Will use embed username if configured.")
	password := flag.String("p", FSpassword, "Specify password to connect to server with. Will use embed password if configured.")
	server := flag.String("fS", FSApplianceFQDN, "Specify server to connect to. Will use embed FQDN if configured.")
	flag.Parse()


	if *username == "" || *password == "" || *server == "" {
		fmt.Println("Username, password, or server not specified.")
		if *username == "" {
			FSusername = StringPrompt("Username:")
		}
		if *password == "" {
			FSpassword = StringPrompt("Password:")
		}
		if *server == "" {
			FSApplianceFQDN = StringPrompt("Forescout Appliance FQDN:")
		}
	}
	FSusername = *username
	FSpassword = *password
	FSApplianceFQDN = *server
	if *test {
		return
	} else if *ZoneName == "" {
		fmt.Println("You must specify a zone name.")
		flag.PrintDefaults()
		return
	} else {
		FSLogin()
		if ConnectTest() {
			fmt.Printf("Successfully logged into %s\n", FSApplianceFQDN)
		} else {
			fmt.Printf("Could not login to %s: \n This could be due to incorrect credentials, or it could not connect to the server.", FSApplianceFQDN)
			return
		}
		check := GetZoneID(*ZoneName)
		if check == "No Zone ID Found." {
			fmt.Println(check)
			return
		}
		timeBasedFilter(*timeFilter)
		if *GetSRCZonesFlag {
			fmt.Println(GetSRCZones(GetZoneID(*ZoneName)))
		} else if *GetDSTZonesFlag {
			fmt.Println(GetDSTZones(GetZoneID(*ZoneName)))
		} else if *CheckZoneID {
			fmt.Println(GetZoneID(*ZoneName))
		} else if *exportDSTDataFlag {
			SRCZone := GetZoneID(*ZoneName)
			var DSTZonesWData []string
			var DSTZonesCollection []string
			dir := fmt.Sprintf("Connections made from %s", *ZoneName)
			os.Mkdir(dir, 0600)
			os.Chdir(dir)
			DSTZones := GetDSTZones(SRCZone)
			for _, DSTZone := range DSTZones {
				val, _ := CheckOccurrences(SRCZone, DSTZone)
				if val {
					DSTZonesWData, _ = DSTzoneToZoneConnections(SRCZone, DSTZone)
					for _, DSTZone = range DSTZonesWData {
						DSTZonesCollection = append(DSTZonesCollection, DSTZone)
					}
				}
			}
			bar := pb.StartNew(len(DSTZonesCollection))
			for _, DSTZone := range DSTZonesCollection {
				ExportData(SRCZone, DSTZone)
				bar.Increment()
			}
			time.Sleep(1 * time.Second)
			fmt.Printf("\nData successfully exported to \"%s\"", dir)

		} else if *exportSRCDataFlag {
			var SRCZonesWData []string
			var SRCZoneCollection []string
			DSTZone := GetZoneID(*ZoneName)
			dir := fmt.Sprintf("Connections made to %s", *ZoneName)
			os.Mkdir(dir, 0600)
			os.Chdir(dir)
			SRCZones := GetSRCZones(DSTZone)
			for _, SRCZone := range SRCZones {
				val, _ := CheckOccurrences(SRCZone, DSTZone)
				if val {
					SRCZonesWData, _ = SRCzoneToZoneConnections(SRCZone, DSTZone)
					for _, SRCZone = range SRCZonesWData {
						SRCZoneCollection = append(SRCZoneCollection, SRCZone)
					}
				}
			}
			bar := pb.StartNew(len(SRCZoneCollection))
			for _, SRCZone := range SRCZoneCollection {
				ExportData(SRCZone, DSTZone)
				bar.Increment()
			}
			time.Sleep(1 * time.Second)
			fmt.Printf("\nData successfully exported to \"%s\"", dir)
		} else {
			flag.PrintDefaults()
		}
	}

}
