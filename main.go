package eyeSegmentAPI

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"github.com/cheggaaa/pb/v3"
	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
	"golang.org/x/term"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// These are global variables that will be used in multiple functions.
var JSESSIONID string
var XSRFTOKEN string
var reUseBody io.ReadCloser

// These are constants that will be used for logging in to the website.
const FSusername = "user"
const FSpassword = "password"
const FSApplianceFQDN = "appliance.forescout.local"

// This function is used to remove a given number of lines from a file.
// fn is the file name, start is the line number to start removing from, and n is the number of lines to remove.
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

// This function is used by the removeLines function.
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

// This function logs in to the website using the constants defined earlier.
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
		selenium.Output(os.Stderr),          // Output debug information to STDERR.
	}

	if service, err = selenium.NewChromeDriverService(chromedriver, port, opts...); err != nil {
		panic(err) // panic is used to handle errors.
	}

	defer service.Stop()

	// Connect to the WebDriver instance running locally.
	caps.AddChrome(chromeopts)
	if wd, err = selenium.NewRemote(caps, fmt.Sprintf("http://localhost:%d/wd/hub", port)); err != nil {
		panic(err)
	}
	defer wd.Quit()

	// Get a session.
	wd.Get(fmt.Sprintf("https://%s/", FSApplianceFQDN))
	time.Sleep(2 * time.Second)

	// Log in to the website.
	elem, _ := wd.FindElement(selenium.ByID, "username")
	elem.SendKeys(FSusername)
	elem, _ = wd.FindElement(selenium.ByID, "password")
	elem.SendKeys(FSpassword)
	elem, _ = wd.FindElement(selenium.ByID, "login-button")
	elem.Click()
	time.Sleep(2 * time.Second)

	// Get the JSESSIONID and XSRFTOKEN values.
	cookies, _ := wd.GetCookies()
	for _, cookie := range cookies {
		if cookie.Name == "JSESSIONID" {
			JSESSIONID = cookie.Value
		} else if cookie.Name == "XSRF-TOKEN" {
			XSRFTOKEN = cookie.Value
		}
	}
}

// This function connects to the configured forescout appliance to ensure connectivity.
func ConnectTest() bool {

	site := fmt.Sprintf("https://%s/seg/api/v1/environment/configuration", FSApplianceFQDN)
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

// Get array of destinations zones 
func GetDSTZones(zoneID string) []string {
	var DSTZones []string
	site := fmt.Sprintf("https://%s/seg/api/v3/matrix/0/policies/visualization?srcZoneId=%s", FSApplianceFQDN, zoneID)
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

// Get array of source zones
func GetSRCZones(zoneID string) []string {
	var SRCZones []string
	site := fmt.Sprintf("https://%s/seg/api/v3/matrix/0/policies/visualization?dstZoneId=%s", FSApplianceFQDN, zoneID)
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

// Get ID of zone given natural name
func GetZoneID(zoneName string) string {
	var ZoneID string

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/seg/api/v1/zone-map/", FSApplianceFQDN), nil)
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

// Remove the beginning and ending quotes of given string
func trimQuote(s string) string {
	if len(s) > 0 && s[0] == '"' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == '"' {
		s = s[:len(s)-1]
	}
	return s
}

// Check if data exists between source and destination zones. Returns bool and error.
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

// Drill down the matrix to the bottom most zones given any combination of source and destination zones. Return array of destinations zones. 
func DSTzoneToZoneConnections(SRCZone string, DSTZone string) ([]string, error) {
	var DSTZones []string
	site := fmt.Sprintf("https://%s/seg/api/v1/zone-to-zone", FSApplianceFQDN)
	method := "POST"

	payload := strings.NewReader(fmt.Sprintf(`{"matrixId":"0","srcZoneId":"%s","dstZoneId":"%s","shouldOnlyShowPolicyViolation":false}`, SRCZone, DSTZone))

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
	}
	req, err := http.NewRequest(method, site, payload)

	if err != nil {
		fmt.Println(err)
		return DSTZones, err
	}
	req.Header.Add("Host", FSApplianceFQDN)
	//req.Header.Add("Content-Length", "125")
	req.Header.Add("Sec-Ch-Ua", "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"")
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")
	req.Header.Add("X-Xsrf-Token", XSRFTOKEN)
	req.Header.Add("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36")
	req.Header.Add("Sec-Ch-Ua-Platform", "\"Windows\"")
	req.Header.Add("Origin", FSApplianceFQDN)
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Sec-Fetch-Mode", "cors")
	req.Header.Add("Sec-Fetch-Dest", "empty")
	req.Header.Add("Referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Connection", "close")
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return DSTZones, err
	}
	defer res.Body.Close()
	// Create a new gzip reader for the response body
	gzr, err := gzip.NewReader(res.Body)
	if err != nil {
		fmt.Println(err)
		return DSTZones, err
	}

	// Read the decompressed response body into memory
	body, err := ioutil.ReadAll(gzr)
	if err != nil {
		fmt.Println(err)
		return DSTZones, err
	}

	// Parse the JSON response
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		panic(err)
	}
	for _, child := range jsonParsed.Path("zoneToZoneConnections").Children() {
		DSTZones = append(DSTZones, trimQuote(child.Path("dstZoneId").String()))
	}
	return DSTZones, nil
}

// Drill down the matrix to the bottom most zones given any combination of source and destination zones. Return array of source zones. 
func SRCzoneToZoneConnections(SRCZone string, DSTZone string) ([]string, error) {
	var SRCZones []string
	site := fmt.Sprintf("https://%s/seg/api/v1/zone-to-zone", FSApplianceFQDN)
	method := "POST"

	payload := strings.NewReader(fmt.Sprintf(`{"matrixId":"0","srcZoneId":"%s","dstZoneId":"%s","shouldOnlyShowPolicyViolation":false}`, SRCZone, DSTZone))

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
	}
	req, err := http.NewRequest(method, site, payload)

	if err != nil {
		fmt.Println(err)
		return SRCZones, err
	}
	req.Header.Add("Host", FSApplianceFQDN)
	//req.Header.Add("Content-Length", "125")
	req.Header.Add("Sec-Ch-Ua", "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"")
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")
	req.Header.Add("X-Xsrf-Token", XSRFTOKEN)
	req.Header.Add("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36")
	req.Header.Add("Sec-Ch-Ua-Platform", "\"Windows\"")
	req.Header.Add("Origin", FSApplianceFQDN)
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Sec-Fetch-Mode", "cors")
	req.Header.Add("Sec-Fetch-Dest", "empty")
	req.Header.Add("Referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Connection", "close")
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return SRCZones, err
	}
	defer res.Body.Close()

	// Create a new gzip reader for the response body
	gzr, err := gzip.NewReader(res.Body)
	if err != nil {
		fmt.Println(err)
		return SRCZones, err
	}

	// Read the decompressed response body into memory
	body, err := ioutil.ReadAll(gzr)
	if err != nil {
		fmt.Println(err)
		return SRCZones, err
	}

	// Parse the JSON response
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		panic(err)
	}
	for _, child := range jsonParsed.Path("zoneToZoneConnections").Children() {
		SRCZones = append(SRCZones, trimQuote(child.Path("srcZoneId").String()))
	}
	return SRCZones, nil
}

// Export csv from given source and destination zone.
func ExportData(SRCZone string, DSTZone string) {
	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
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

// Search back the number of days by given int. Default is 3 day lookback
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

// Clear any filter or time range from previous sessions
func ClearFilter() {

	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DisableCompression: true,
	}

	client := &http.Client{
		Transport: transport,
	}

	url := fmt.Sprintf("https://%s/seg/api/v2/filter", FSApplianceFQDN)
	method := "POST"

	//url := "https://10.9.0.10/seg/api/v2/filter"
	//method := "POST"
	//
	payload := strings.NewReader(`{"srcZones":[],"dstZones":[],"services":[],"protocols":[],"isExclude":false,"filterEnabled":false,"hasFilters":true,"srcIp":"","dstIp":"","timeRangeFilter":null}`)
	//
	//client := &http.Client {
	//}
	req, err := http.NewRequest(method, url, payload)

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

	//body, err := ioutil.ReadAll(res.Body)
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//fmt.Println(string(body))
}

// Securely prompt for password in the cli
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
	username := flag.String("u", "", "Specify username to connect to server with. Will use embedded username if configured.")
	password := flag.String("p", "", "Specify password to connect to server with. Will use embedded password if configured.")
	server := flag.String("fS", FSApplianceFQDN, "Specify server to connect to. Will use embedded FQDN if configured.")
	flag.Parse()
	if FSApplianceFQDN == "" || FSusername == "" || FSpassword == "" {
		if *username == "" && FSusername == "" {
			if FSusername == "" && *username != "" {
				FSusername = *username
			} else {
				fmt.Println("Username not specified.")
				FSusername = StringPrompt("Username:")
			}
		}
		if *password == "" && FSpassword == "" {
			if FSpassword == "" && *password != "" {
				FSpassword = *password
			} else {
				fmt.Println("Password not specified.")
				FSpassword = StringPrompt("Username:")
			}
		}
		if *server == "" && FSApplianceFQDN == "" {
			if FSApplianceFQDN == "" && *server != "" {
				FSApplianceFQDN = *server
			} else {
				fmt.Println("Server not specified.")
				FSApplianceFQDN = StringPrompt("Forescout Appliance FQDN:")
			}
		}
	}

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
		ClearFilter()
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
