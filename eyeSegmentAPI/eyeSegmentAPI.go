package eyeSegmentAPI

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/spf13/viper"

	"golang.org/x/term"
)

// These are constants that will be used for logging in to the website. Create a "helper.yml" and paste in the below data
// Please encrypt your individual credentials before saving and paste in the 32-bit key below
// helper:
//
//	  username:
//		 password:
//		 url:
//
// These are global variables that will be used in multiple functions.
var (
	FSusername      string
	FSpassword      string
	FSApplianceFQDN string
	JSESSIONID      string
	XSRFTOKEN       string
	reUseBody       io.ReadCloser
)

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

// CheckError : default error checker. Built in if statement.
func CheckError(err error) {
	if err != nil {
		log.Fatal(err)
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
	if b, err = io.ReadAll(f); err != nil {
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

// FSLogin : This function logs in to the website using the constants defined earlier.
func FSLogin() {
	// Start a new headless Chrome browser
	l := launcher.New().Leakless(false).Headless(true)
	//l = l.Set(flags.ProxyServer, "127.0.0.1:8080")
	controlURL, _ := l.Launch()
	ctx := rod.New().ControlURL(controlURL).MustConnect().MustIncognito()
	ctx.MustIgnoreCertErrors(true)

	router := ctx.HijackRequests()
	router.MustAdd("*", func(hijack *rod.Hijack) {
		if strings.Contains(hijack.Request.URL().String(), "/seg/api/v1/zone-map/") {
			for _, cookie := range hijack.Request.Headers() {
				if strings.Contains(cookie.String(), "JSESSIONID") {
					JsessionidRegex := regexp.MustCompile(`JSESSIONID=.*?;`)
					JSESSIONID = strings.ReplaceAll(strings.ReplaceAll(JsessionidRegex.FindString(cookie.String()), "JSESSIONID=", ""), ";", "")
					XsrftokenRegex := regexp.MustCompile(`XSRF-TOKEN=.*`)
					XSRFTOKEN = strings.ReplaceAll(XsrftokenRegex.FindString(cookie.String()), "XSRF-TOKEN=", "")
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

	page.MustElement("body > app-root > main-topbar > nav > ul:nth-child(2) > div:nth-child(2) > li").MustClick()
	page.MustWaitLoad()
	time.Sleep(2 * time.Second)
	page.MustClose()
	router.MustStop()
	ctx.MustClose()
	l.Kill()
	l.Cleanup()
}

// ConnectTest : This function connects to the configured forescout appliance to ensure connectivity.
func ConnectTest() bool {

	body := buildRequest("/seg/api/v1/environment/configuration", http.MethodGet)

	if len(body) == 0 {
		return false
	} else {
		return true
	}
}

// GetDSTZones : Get array of destinations zones
func GetDSTZones(zoneID string) []string {
	var DSTZones []string
	body := buildRequest(fmt.Sprintf("/seg/api/v1/policies/visualization?matrixId=0&srcZoneId=%s", zoneID), http.MethodGet)
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		log.Fatal(err)
	}
	for _, child := range jsonParsed.Children() {
		DSTZones = append(DSTZones, trimQuote(child.Path("dstZoneId").String()))
	}
	return DSTZones
}

// GetSRCZones : Get array of source zones
func GetSRCZones(zoneID string) []string {
	var SRCZones []string
	body := buildRequest(fmt.Sprintf("/seg/api/v1/policies/visualization?matrixId=0&dstZoneId=%s", zoneID), http.MethodGet)

	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		log.Fatal(err)
	}
	for _, child := range jsonParsed.Children() {
		SRCZones = append(SRCZones, trimQuote(child.Path("srcZoneId").String()))
	}

	return SRCZones
}

// Build the api request with headers and transport methods and process the response
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
		log.Println(err)
		return nil
	}
	req.Header.Set("authority", FSApplianceFQDN)
	req.Header.Set("accept", "application/json, text/plain, */*")
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
	req.Header.Set("referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		return nil
	}
	return body
}

// GetZoneID : Get ID of zone given natural name
func GetZoneID(zoneName string) string {
	fmt.Println("Gathering Zone ID for processing")
	var ZoneID string

	body := buildRequest("/seg/api/v1/zone-map/", http.MethodGet)
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		log.Fatal(err)
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

// CheckOccurrences : Check if data exists between source and destination zones. Returns bool and error.
func CheckOccurrences(SRCZone string, DSTZone string) (bool, error) {
	fmt.Println("Checking Occurrences: " + "Source Zone: " + SRCZone + ", Destination Zone: " + DSTZone)
	body := buildRequest(fmt.Sprintf("/seg/api/v3/matrix/data/0/occurrences-by-port-range?srcZoneId=%s&dstZoneId=%s&shouldOnlyShowPolicyViolation=false", SRCZone, DSTZone), http.MethodGet)
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		log.Fatal(err)
	}
	if len(jsonParsed.Children()) == 0 {
		return false, nil
	} else {
		return true, nil
	}
}

// Function to build Post Request from given endpoint path, method (ie. POST, PUT), payload, and compression bool
func buildPostRequest(apiUri string, method string, payload string, DisableCompress bool) []byte {
	site := fmt.Sprintf("https://" + FSApplianceFQDN + apiUri)
	var transport *http.Transport
	if !DisableCompress {
		transport = &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			DisableCompression: true,
		}
	} else {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &http.Client{
		Transport: transport,
	}
	req, err := http.NewRequest(method, site, strings.NewReader(payload))

	if err != nil {
		log.Println(err)
		return nil
	}
	if !DisableCompress {
		req.Header.Add("Accept-Encoding", "gzip, deflate")
	}
	req.Header.Add("Host", FSApplianceFQDN)
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")
	req.Header.Add("X-Xsrf-Token", XSRFTOKEN)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36")
	req.Header.Add("Origin", fmt.Sprintf("https://%s", FSApplianceFQDN))
	req.Header.Set("Referer", fmt.Sprintf("https://%s/forescout-client/", FSApplianceFQDN))

	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)

	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer res.Body.Close()
	var body []byte
	if !DisableCompress {
		gzr, err := gzip.NewReader(res.Body)
		if err != nil {
			log.Println(err)
			return nil
		}
		// Read the decompressed response body into memory
		body, err = io.ReadAll(gzr)
		if err != nil {
			log.Println(err)
			return nil
		}
	} else {
		body, err = io.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}
	}

	return body
}

// DSTzoneToZoneConnections : Drill down the matrix to the bottom most zones given any combination of source and destination zones. Return array of destinations zones.
func DSTzoneToZoneConnections(SRCZone string, DSTZone string) ([]string, error) {
	//fmt.Println("Reading DST Zone to Zone Connections")
	var DSTZones []string

	body := buildPostRequest("/seg/api/v1/zone-to-zone", http.MethodPost, fmt.Sprintf(`{"matrixId":"0","srcZoneId":"%s","dstZoneId":"%s","shouldOnlyShowPolicyViolation":false}`, SRCZone, DSTZone), false)

	// Parse the JSON response
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		log.Fatal(err)
	}
	for _, child := range jsonParsed.Path("zoneToZoneConnections").Children() {
		DSTZones = append(DSTZones, trimQuote(child.Path("dstZoneId").String()))
	}
	return DSTZones, nil
}

// SRCzoneToZoneConnections : Drill down the matrix to the bottom most zones given any combination of source and destination zones. Return array of source zones.
func SRCzoneToZoneConnections(SRCZone string, DSTZone string) ([]string, error) {
	//fmt.Println("Reading SRC Zone to Zone Connections")
	var SRCZones []string

	body := buildPostRequest("/seg/api/v1/zone-to-zone", http.MethodPost, fmt.Sprintf(`{"matrixId":"0","srcZoneId":"%s","dstZoneId":"%s","shouldOnlyShowPolicyViolation":false}`, SRCZone, DSTZone), false)

	// Parse the JSON response
	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		log.Fatal(err)
	}
	for _, child := range jsonParsed.Path("zoneToZoneConnections").Children() {
		SRCZones = append(SRCZones, trimQuote(child.Path("srcZoneId").String()))
	}
	return SRCZones, nil
}

// GetCSVData returns the csv data as io.reader
func GetCSVData(SRCZone string, DSTZone string) io.Reader {
	body := buildPostRequest("/seg/api/v3/matrix/data/0/services-export", http.MethodPost, fmt.Sprintf(`{"srcZoneId":"%s","dstZoneId":"%s","shouldOnlyShowPolicyViolation":false}`, SRCZone, DSTZone), true)

	var bodyTextString = string(body)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "Source_Zone") {
			bodyTextString = strings.ReplaceAll(bodyTextString, line, "")
		} else {
			break
		}
	}
	return strings.NewReader(strings.TrimSpace(bodyTextString))
}

// ExportCSVData : Export csv from given source and destination zone.
func ExportCSVData(SRCZone string, DSTZone string) {
	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DisableCompression: true,
	}

	client := &http.Client{
		Transport: transport,
	}

	site := fmt.Sprintf("https://%s/seg/api/v3/matrix/data/0/services-export", FSApplianceFQDN)
	method := http.MethodPost

	payloadFormat := fmt.Sprintf(`{"srcZoneId":"%s","dstZoneId":"%s","shouldOnlyShowPolicyViolation":false}`, SRCZone, DSTZone)
	payload := strings.NewReader(payloadFormat)
	req, err := http.NewRequest(method, site, payload)

	if err != nil {
		log.Println(err)
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
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Connection", "close")
	user := fmt.Sprintf("%%22%s%%22", FSusername)
	Cookies := fmt.Sprintf("JSESSIONID=%v; user=%v; XSRF-TOKEN=%v", JSESSIONID, user, XSRFTOKEN)
	req.Header.Set("Cookie", Cookies)
	req.Header.Set("X-Xsrf-Token", XSRFTOKEN)

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
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

	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(filename, bodyText, 644)
	if err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()

	f, _ := os.Open(filename)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "Source_Zone") {
			err = removeLines(filename, 1, 1)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			break
		}
	}

}

// TimeBasedFilter : Search back the number of days by given int. Default is 3 day look back
func TimeBasedFilter(days int) {
	//fmt.Println("Applying filter based on days specified")
	//body := buildPostRequest("/seg/api/v1/user/configuration/timeBasedFilter", http.MethodPut, fmt.Sprintf("{\"lastDaysFilter\":%d}", days), false)
	buildPostRequest("/seg/api/v1/user/configuration/timeBasedFilter", http.MethodPut, fmt.Sprintf("{\"lastDaysFilter\":%d}", days), false)
	//fmt.Println(string(body))
}

// ClearFilter : Clear any filter or time range from previous sessions
func ClearFilter() {
	buildPostRequest("/seg/api/v2/filter", http.MethodPost, `{"srcZones":[],"dstZones":[],"services":[],"protocols":[],"isExclude":false,"filterEnabled":false,"hasFilters":true,"srcIp":"","dstIp":"","timeRangeFilter":null}`, true)
}

// GetFilter : Get current filter settings
func GetFilter() string {
	return string(buildRequest("/seg/api/v2/filter", http.MethodGet))
}

// SetFilter : Set filter for matrix
// Example payload: ({"srcZones":[""],"dstZones":[""],"services":[],"isExclude":false,"protocols":[],"srcIp":"","dstIp":"","hasFilters":true,"filterEnabled":true,"confidence":null})
func SetFilter(filterPayload string) string {
	return string(buildPostRequest("/seg/api/v2/filter", http.MethodPost, filterPayload, false))
}

// GetMatrixData : Get all data in Matrix (best used with SetFilter).
func GetMatrixData() []byte {
	return buildRequest("/seg/api/v2/matrix/data/0/traffic?shouldOnlyShowPolicyViolation=false", http.MethodGet)
}

// StringPrompt : Securely prompt for password in the cli
func StringPrompt(label string) string {
	var s string
	r := bufio.NewReader(os.Stdin)
	_, err := fmt.Fprint(os.Stderr, fmt.Sprintf("%s ", label))
	if err != nil {
		log.Fatal(err)
	}
	if label == "Password:" {
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
		s = string(bytePassword)
	} else {
		for {
			s, _ = r.ReadString('\n')
			if s != "" {
				break
			}
		}
	}
	return strings.TrimSpace(s)
}

// GetCredentialsFromFiles : Read Forescout credentials from encrypted file.
func GetCredentialsFromFiles() bool {
	viper.AddConfigPath(".")
	viper.SetConfigName("key") // Register config file name (no extension)
	viper.SetConfigType("yml") // Look for specific type
	var err = viper.ReadInConfig()
	//CheckError(err)
	if err != nil {
		return false
	}
	appCode = viper.GetString("helper.key")

	viper.SetConfigName("helper") // Change file and reread contents.
	err = viper.ReadInConfig()
	CheckError(err)

	FSusername = passBall(viper.GetString("helper.username"))
	FSpassword = passBall(viper.GetString("helper.password"))
	FSApplianceFQDN = viper.GetString("helper.url")
	return true
}
