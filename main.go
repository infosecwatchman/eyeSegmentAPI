package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/cheggaaa/pb/v3"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/spf13/viper"

	"golang.org/x/term"
)

// These are global variables that will be used in multiple functions.
var JSESSIONID string
var XSRFTOKEN string
var reUseBody io.ReadCloser

// These are constants that will be used for logging in to the website. Create a "helper.yml" and paste in the below data
// Please encrypt your individual credentials before saving and paste in the 32 bit key below
// helper:
//
//	  username:
//		 password:
//		 url:
var FSusername string
var FSpassword string
var FSApplianceFQDN string

// encryption key used to decrypt helper.yml
// create 'helper.key' file to store appCode. Copy below code format for yml
// helper:
//
//	key: 'fasdfasdfasdfasdf'
var appCode string

// This function is used to pass encrypted credentials.
// Don't forget to update the appCode with a new 32 bit string per application.
func passBall(ct string) string {
	var plaintext []byte
	ciphertext, _ := hex.DecodeString(ct)
	c, err := aes.NewCipher([]byte(appCode))
	CheckError(err)

	gcm, err := cipher.NewGCM(c)
	CheckError(err)

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err = gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	CheckError(err)

	return string(plaintext)
}

// default error checker. Built in if statement.
func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

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
	// Start a new headless Chrome browser
	l := launcher.New().Leakless(false) //.Headless(true)
	//l = l.Set(flags.ProxyServer, "127.0.0.1:8080")
	controlURL, _ := l.Launch()
	ctx := rod.New().ControlURL(controlURL).MustConnect().MustIncognito()
	ctx.MustIgnoreCertErrors(true)

	router := ctx.HijackRequests()
	router.MustAdd("*", func(hijack *rod.Hijack) {
		if strings.Contains(hijack.Request.URL().String(), "/seg/api/v1/zone-map/") {
			for _, cookie := range hijack.Request.Headers() {
				if strings.Contains(cookie.String(), "JSESSIONID") {
					JSESSIONID_regex := regexp.MustCompile(`JSESSIONID=.*?;`)
					JSESSIONID = strings.ReplaceAll(strings.ReplaceAll(JSESSIONID_regex.FindString(cookie.String()), "JSESSIONID=", ""), ";", "")
					XSRFTOKEN_regex := regexp.MustCompile(`XSRF-TOKEN=.*`)
					XSRFTOKEN = strings.ReplaceAll(XSRFTOKEN_regex.FindString(cookie.String()), "XSRF-TOKEN=", "")
				}
				hijack.ContinueRequest(&proto.FetchContinueRequest{})
			}
			hijack.ContinueRequest(&proto.FetchContinueRequest{})
		} else {
			hijack.ContinueRequest(&proto.FetchContinueRequest{})
		}
	})
	go router.Run()
	// Navigate to a web page
	page := ctx.MustPage()
	page = page.MustNavigate(fmt.Sprintf("https://%s/forescout-client", FSApplianceFQDN))
	// Fill out a form and submit it
	page.MustElement("#username").MustInput(FSusername)
	page.MustElement("#password").MustInput(FSpassword)
	page.KeyActions().Press(input.Enter).MustDo()
	time.Sleep(2 * time.Second)
	page.MustWaitLoad()

	page.MustElement("body > app-root > main-topbar > nav > ul:nth-child(2) > div:nth-child(2) > li > a").MustClick()
	page.MustWaitLoad()
	time.Sleep(2 * time.Second)
	//fmt.Printf("JSESSIONID: %s\nXSRF: %s\n", JSESSIONID, XSRFTOKEN)
	page.MustClose()
	router.MustStop()
	ctx.MustClose()
	l.Kill()
	l.Cleanup()
}

// This function connects to the configured forescout appliance to ensure connectivity.
func ConnectTest() bool {

	body := buildRequest("/seg/api/v1/environment/configuration", "GET")

	if len(body) == 0 {
		return false
	} else {
		return true
	}
}

// Get array of destinations zones
func GetDSTZones(zoneID string) []string {
	var DSTZones []string
	body := buildRequest("/seg/api/v1/policies/visualization?matrixId=0&srcZoneId="+zoneID, "GET")
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		panic(err)
	}
	for _, child := range jsonParsed.Children() {
		DSTZones = append(DSTZones, trimQuote(child.Path("dstZoneId").String()))
	}
	return DSTZones
}

// Get array of source zones
func GetSRCZones(zoneID string) []string {
	var SRCZones []string
	body := buildRequest("/seg/api/v1/policies/visualization?matrixId=0&dstZoneId="+zoneID, "GET")

	//fmt.Print(body)
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		panic(err)
	}
	for _, child := range jsonParsed.Children() {
		SRCZones = append(SRCZones, trimQuote(child.Path("srcZoneId").String()))
	}

	return SRCZones
}

// build the api request with headers and transport methods and process the response
func buildRequest(apiUri string, method string) []byte {
	site := fmt.Sprintf("https://" + FSApplianceFQDN + apiUri)

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
	req.Header.Set("TE", "Trailers")
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
	//fmt.Print(body)
	//	jsonParsed, err := gabs.ParseJSON(body)
	//	if err != nil {
	//panic(err)
	//	}
	return body
}

// Get ID of zone given natural name
func GetZoneID(zoneName string) string {
	fmt.Println("Gathering Zone ID for processing")
	var ZoneID string

	body := buildRequest("/seg/api/v1/zone-map/", "GET")
	jsonParsed, err := gabs.ParseJSON(body)
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
	fmt.Println("Zone ID for " + zoneName + " is " + ZoneID)
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
	fmt.Println("Checking Occurrences: " + "Source Zone: " + SRCZone + ", Destination Zone: " + DSTZone)
	body := buildRequest(fmt.Sprintf("/seg/api/v3/matrix/data/0/occurrences-by-port-range?srcZoneId=%s&dstZoneId=%s&shouldOnlyShowPolicyViolation=false", SRCZone, DSTZone), "GET")
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

func buildPostRequest(apiUri string, method string, payload string, compress bool) []byte {
	site := fmt.Sprintf("https://" + FSApplianceFQDN + apiUri)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
	}
	req, err := http.NewRequest(method, site, strings.NewReader(payload))

	if err != nil {
		fmt.Println(err)
		return nil
	}
	req.Header.Add("Host", FSApplianceFQDN)
	//req.Header.Add("Content-Length", "125")
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")
	req.Header.Add("X-Xsrf-Token", XSRFTOKEN)
	req.Header.Add("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36")
	req.Header.Add("Origin", fmt.Sprintf("https://%s", FSApplianceFQDN))
	req.Header.Set("Referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Connection", "close")
	req.Header.Add("Sec-Ch-Ua", "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"")
	req.Header.Add("Sec-Fetch-Site", "same-origin")
	req.Header.Add("Sec-Fetch-Mode", "cors")
	req.Header.Add("Sec-Fetch-Dest", "empty")
	req.Header.Add("Sec-Ch-Ua-Platform", "\"Windows\"")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")

	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer res.Body.Close()

	gzr, err := gzip.NewReader(res.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	// Read the decompressed response body into memory
	body, err := ioutil.ReadAll(gzr)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	//fmt.Print(body)
	//	jsonParsed, err := gabs.ParseJSON(body)
	//	if err != nil {
	//panic(err)
	//	}
	return body
}

// Drill down the matrix to the bottom most zones given any combination of source and destination zones. Return array of destinations zones.
func DSTzoneToZoneConnections(SRCZone string, DSTZone string) ([]string, error) {
	fmt.Println("Reading DST Zone to Zone Connections")
	var DSTZones []string

	body := buildPostRequest("/seg/api/v1/zone-to-zone", "POST", fmt.Sprintf(`{"matrixId":"0","srcZoneId":"%s","dstZoneId":"%s","shouldOnlyShowPolicyViolation":false}`, SRCZone, DSTZone), true)

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
	fmt.Println("Reading SRC Zone to Zone Connections")
	var SRCZones []string

	body := buildPostRequest("/seg/api/v1/zone-to-zone", "POST", fmt.Sprintf(`{"matrixId":"0","srcZoneId":"%s","dstZoneId":"%s","shouldOnlyShowPolicyViolation":false}`, SRCZone, DSTZone), true)

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
	fmt.Println("Applying filter based on days specified")
	body := buildPostRequest("/seg/api/v1/user/configuration/timeBasedFilter", "PUT", fmt.Sprintf("{\"lastDaysFilter\":%d}", days), false)

	fmt.Println(string(body))
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

	payload := strings.NewReader(`{"srcZones":[],"dstZones":[],"services":[],"protocols":[],"isExclude":false,"filterEnabled":false,"hasFilters":true,"srcIp":"","dstIp":"","timeRangeFilter":null}`)

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

	viper.AddConfigPath(".")
	viper.SetConfigName("key") // Register config file name (no extension)
	viper.SetConfigType("yml") // Look for specific type
	var err = viper.ReadInConfig()
	CheckError(err)

	appCode = viper.GetString("helper.key")

	viper.SetConfigName("helper") // Change file and reread contents.
	err = viper.ReadInConfig()
	CheckError(err)

	FSusername = passBall(viper.GetString("helper.username"))
	FSpassword = passBall(viper.GetString("helper.password"))
	FSApplianceFQDN = viper.GetString("helper.url")

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
		fmt.Println("Attempting connection to your local forescout instance via " + FSApplianceFQDN + ". Please wait.....")
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
			fmt.Println("Creating Directory of Connections")
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
