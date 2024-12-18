package main

import (
	"JUS/backend/login"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Application ApiAppKey
const ApiAppKey = "APIDEYm569rA26E170B6Z9h5gppooHg3Wt7z0ovR"

// Application ApiAppSecret
const ApiAppSecret = "6vsZO2d2d4382ovof3I5597fv7WPsi48PLf7Mub5"

const GmtFormat = "Mon, 02 Jan 2006 15:04:05 GMT"
const Accept = "application/json"
const ContentType = "application/json"

// ROBOT SN
// puddbot "6e0328220470075"
// t300 "826094814050002"
// t300 murata "826094814050005"
const sn = "826094814050005"
const mapData = "0#0#แผนที่Test"
const img = "https://www.google.com/url?sa=i&url=https%3A%2F%2Fm.youtube.com%2F%40saleozone360&psig=AOvVaw3Zadp6Bb7zDX3Peq6Qb0wU&ust=1733630267685000&source=images&cd=vfe&opi=89978449&ved=0CBQQjRxqFwoTCPjY6pPilIoDFQAAAAAdAAAAABAE"

// destination ponit
const ponit1 = "A1_D"
const ponit2 = "A2_D"
const ponit3 = "B1_D"
const ponit4 = "B2_D"

// Shop Part
const Shopid = "44715000"

func main() {
	r := mux.NewRouter()

	// Wrap your handlers with CORS middleware
	r.HandleFunc("/chackapi", corsMiddleware(chackapi)).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/post/job1", corsMiddleware(addjob1)).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/post/job2", corsMiddleware(addjob2)).Methods("POST", "OPTIONS")
	r.HandleFunc("/register", login.RegisterUser).Methods("POST")
	r.HandleFunc("/login", login.LoginUser).Methods("POST")
	r.HandleFunc("/call", corsMiddleware(call)).Methods("POST", "OPTIONS")
	r.HandleFunc("/maplist", corsMiddleware(maplist)).Methods("GET", "OPTIONS")
	r.HandleFunc("/sandtaskjob10s", corsMiddleware(sandtaskjob10s)).Methods("POST", "OPTIONS")
	r.HandleFunc("/sandtaskjob20s", corsMiddleware(sandtaskjob20s)).Methods("POST", "OPTIONS")
	r.HandleFunc("/wheretherobot", corsMiddleware(wheretherobot)).Methods("GET", "OPTIONS")
	r.HandleFunc("/cancelthetask", corsMiddleware(cancelthetask)).Methods("POST", "OPTIONS")
	r.HandleFunc("/machine_is_currently_using_the_map", corsMiddleware(machine_is_currently_using_the_map)).Methods("GET", "OPTIONS")
	r.HandleFunc("/the_specified_bot_status", corsMiddleware(the_specified_bot_status)).Methods("GET", "OPTIONS")
	r.HandleFunc("/formuratatestcase", corsMiddleware(formuratatestcase)).Methods("POST", "OPTIONS")
	r.HandleFunc("/list_of_stores", corsMiddleware(list_of_stores)).Methods("GET", "OPTIONS")
	r.HandleFunc("/list_of_machines", corsMiddleware(list_of_machines)).Methods("GET", "OPTIONS")
	r.HandleFunc("/list_of_map", corsMiddleware(list_of_map)).Methods("GET", "OPTIONS")
	r.HandleFunc("/the_real_time_map_location_of_the_machine", corsMiddleware(the_real_time_map_location_of_the_machine)).Methods("GET", "OPTIONS")
	r.HandleFunc("/Machine_task_analysis", corsMiddleware(Machine_task_analysis)).Methods("GET", "OPTIONS")
	r.HandleFunc("/Overview_of_the_machine", corsMiddleware(Overview_of_the_machine)).Methods("GET", "OPTIONS")
	r.HandleFunc("/report_the_location", corsMiddleware(report_the_location)).Methods("POST", "OPTIONS")

	// Start the server
	fmt.Println("Starting server on :3030")
	if err := http.ListenAndServe(":3030", r); err != nil {
		log.Fatal("Server failed:", err)
	}
}
func Machine_task_analysis(w http.ResponseWriter, r *http.Request) {

	var Url = fmt.Sprintf("https://css-open-platform.pudutech.com/pudu-entry/data-board/v1/analysis/task/delivery?timezone_offset=8&start_time=1693497600&end_time=1693670399&shop_id=%s0&time_unit=day", Shopid)

	const HTTPMethod = "GET"

	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	Host := u.Hostname()
	Path := u.Path
	Query := u.RawQuery

	Path = strings.TrimPrefix(Path, "/release")
	Path = strings.TrimPrefix(Path, "/test")
	Path = strings.TrimPrefix(Path, "/prepub")
	if Path == "" {
		Path = "/"
	}

	if len(Query) > 0 {
		args, _ := url.ParseQuery(Query)
		var keys []string
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sortQuery := ""
		for _, k := range keys {
			if args[k][0] != "" {
				sortQuery += "&" + k + "=" + args[k][0]
			} else {
				sortQuery += "&" + k
			}
		}
		sortQuery = strings.TrimPrefix(sortQuery, "&")
		Path = Path + "?" + sortQuery
	}

	xDate := time.Now().UTC().Format(GmtFormat)

	ContentMD5 := ""
	bodyStr := ``
	if HTTPMethod == "POST" {
		h := md5.New()
		h.Write([]byte(bodyStr))
		md5Str := hex.EncodeToString(h.Sum(nil))
		ContentMD5 = base64.StdEncoding.EncodeToString([]byte(md5Str))
	}

	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)

	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(bodyStr))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}
func Overview_of_the_machine(w http.ResponseWriter, r *http.Request) {

	var Url = fmt.Sprintf("https://css-open-platform.pudutech.com/pudu-entry/data-board/v1/brief/robot")

	const HTTPMethod = "GET"

	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	Host := u.Hostname()
	Path := u.Path
	Query := u.RawQuery

	Path = strings.TrimPrefix(Path, "/release")
	Path = strings.TrimPrefix(Path, "/test")
	Path = strings.TrimPrefix(Path, "/prepub")
	if Path == "" {
		Path = "/"
	}

	if len(Query) > 0 {
		args, _ := url.ParseQuery(Query)
		var keys []string
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sortQuery := ""
		for _, k := range keys {
			if args[k][0] != "" {
				sortQuery += "&" + k + "=" + args[k][0]
			} else {
				sortQuery += "&" + k
			}
		}
		sortQuery = strings.TrimPrefix(sortQuery, "&")
		Path = Path + "?" + sortQuery
	}

	xDate := time.Now().UTC().Format(GmtFormat)

	ContentMD5 := ""
	bodyStr := ``
	if HTTPMethod == "POST" {
		h := md5.New()
		h.Write([]byte(bodyStr))
		md5Str := hex.EncodeToString(h.Sum(nil))
		ContentMD5 = base64.StdEncoding.EncodeToString([]byte(md5Str))
	}

	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)

	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(bodyStr))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func the_specified_bot_status(w http.ResponseWriter, r *http.Request) {

	var Url = fmt.Sprintf("https://css-open-platform.pudutech.com/pudu-entry/open-platform-service/v1/status/get_by_sn?sn=%s", sn)

	const HTTPMethod = "GET"

	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	Host := u.Hostname()
	Path := u.Path
	Query := u.RawQuery

	Path = strings.TrimPrefix(Path, "/release")
	Path = strings.TrimPrefix(Path, "/test")
	Path = strings.TrimPrefix(Path, "/prepub")
	if Path == "" {
		Path = "/"
	}

	if len(Query) > 0 {
		args, _ := url.ParseQuery(Query)
		var keys []string
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sortQuery := ""
		for _, k := range keys {
			if args[k][0] != "" {
				sortQuery += "&" + k + "=" + args[k][0]
			} else {
				sortQuery += "&" + k
			}
		}
		sortQuery = strings.TrimPrefix(sortQuery, "&")
		Path = Path + "?" + sortQuery
	}

	xDate := time.Now().UTC().Format(GmtFormat)

	ContentMD5 := ""
	bodyStr := ``
	if HTTPMethod == "POST" {
		h := md5.New()
		h.Write([]byte(bodyStr))
		md5Str := hex.EncodeToString(h.Sum(nil))
		ContentMD5 = base64.StdEncoding.EncodeToString([]byte(md5Str))
	}

	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)

	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(bodyStr))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func list_of_stores(w http.ResponseWriter, r *http.Request) {

	var Url = fmt.Sprintf("https://css-open-platform.pudutech.com/pudu-entry/data-open-platform-service/v1/api/shop")

	const HTTPMethod = "GET"

	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	Host := u.Hostname()
	Path := u.Path
	Query := u.RawQuery

	Path = strings.TrimPrefix(Path, "/release")
	Path = strings.TrimPrefix(Path, "/test")
	Path = strings.TrimPrefix(Path, "/prepub")
	if Path == "" {
		Path = "/"
	}

	if len(Query) > 0 {
		args, _ := url.ParseQuery(Query)
		var keys []string
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sortQuery := ""
		for _, k := range keys {
			if args[k][0] != "" {
				sortQuery += "&" + k + "=" + args[k][0]
			} else {
				sortQuery += "&" + k
			}
		}
		sortQuery = strings.TrimPrefix(sortQuery, "&")
		Path = Path + "?" + sortQuery
	}

	xDate := time.Now().UTC().Format(GmtFormat)

	ContentMD5 := ""
	bodyStr := ``
	if HTTPMethod == "POST" {
		h := md5.New()
		h.Write([]byte(bodyStr))
		md5Str := hex.EncodeToString(h.Sum(nil))
		ContentMD5 = base64.StdEncoding.EncodeToString([]byte(md5Str))
	}

	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)

	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(bodyStr))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func list_of_machines(w http.ResponseWriter, r *http.Request) {

	var Url = fmt.Sprintf("https://css-open-platform.pudutech.com/pudu-entry/data-open-platform-service/v1/api/robot")

	const HTTPMethod = "GET"

	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	Host := u.Hostname()
	Path := u.Path
	Query := u.RawQuery

	Path = strings.TrimPrefix(Path, "/release")
	Path = strings.TrimPrefix(Path, "/test")
	Path = strings.TrimPrefix(Path, "/prepub")
	if Path == "" {
		Path = "/"
	}

	if len(Query) > 0 {
		args, _ := url.ParseQuery(Query)
		var keys []string
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sortQuery := ""
		for _, k := range keys {
			if args[k][0] != "" {
				sortQuery += "&" + k + "=" + args[k][0]
			} else {
				sortQuery += "&" + k
			}
		}
		sortQuery = strings.TrimPrefix(sortQuery, "&")
		Path = Path + "?" + sortQuery
	}

	xDate := time.Now().UTC().Format(GmtFormat)

	ContentMD5 := ""
	bodyStr := ``
	if HTTPMethod == "POST" {
		h := md5.New()
		h.Write([]byte(bodyStr))
		md5Str := hex.EncodeToString(h.Sum(nil))
		ContentMD5 = base64.StdEncoding.EncodeToString([]byte(md5Str))
	}

	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)

	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(bodyStr))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func list_of_map(w http.ResponseWriter, r *http.Request) {

	var Url = fmt.Sprintf("https://css-open-platform.pudutech.com/pudu-entry/data-open-platform-service/v1/api/maps")

	const HTTPMethod = "GET"

	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	Host := u.Hostname()
	Path := u.Path
	Query := u.RawQuery

	Path = strings.TrimPrefix(Path, "/release")
	Path = strings.TrimPrefix(Path, "/test")
	Path = strings.TrimPrefix(Path, "/prepub")
	if Path == "" {
		Path = "/"
	}

	if len(Query) > 0 {
		args, _ := url.ParseQuery(Query)
		var keys []string
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sortQuery := ""
		for _, k := range keys {
			if args[k][0] != "" {
				sortQuery += "&" + k + "=" + args[k][0]
			} else {
				sortQuery += "&" + k
			}
		}
		sortQuery = strings.TrimPrefix(sortQuery, "&")
		Path = Path + "?" + sortQuery
	}

	xDate := time.Now().UTC().Format(GmtFormat)

	ContentMD5 := ""
	bodyStr := ``
	if HTTPMethod == "POST" {
		h := md5.New()
		h.Write([]byte(bodyStr))
		md5Str := hex.EncodeToString(h.Sum(nil))
		ContentMD5 = base64.StdEncoding.EncodeToString([]byte(md5Str))
	}

	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)

	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(bodyStr))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func the_real_time_map_location_of_the_machine(w http.ResponseWriter, r *http.Request) {

	var Url = fmt.Sprintf("https://css-open-platform.pudutech.com/pudu-entry/data-open-platform-service/v1/api/map/robotCurrentPosition?shopId=%s&sn=%s", Shopid, sn)

	const HTTPMethod = "GET"

	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	Host := u.Hostname()
	Path := u.Path
	Query := u.RawQuery

	Path = strings.TrimPrefix(Path, "/release")
	Path = strings.TrimPrefix(Path, "/test")
	Path = strings.TrimPrefix(Path, "/prepub")
	if Path == "" {
		Path = "/"
	}

	if len(Query) > 0 {
		args, _ := url.ParseQuery(Query)
		var keys []string
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sortQuery := ""
		for _, k := range keys {
			if args[k][0] != "" {
				sortQuery += "&" + k + "=" + args[k][0]
			} else {
				sortQuery += "&" + k
			}
		}
		sortQuery = strings.TrimPrefix(sortQuery, "&")
		Path = Path + "?" + sortQuery
	}

	xDate := time.Now().UTC().Format(GmtFormat)

	ContentMD5 := ""
	bodyStr := ``
	if HTTPMethod == "POST" {
		h := md5.New()
		h.Write([]byte(bodyStr))
		md5Str := hex.EncodeToString(h.Sum(nil))
		ContentMD5 = base64.StdEncoding.EncodeToString([]byte(md5Str))
	}

	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)

	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(bodyStr))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

// use get mathod
func machine_is_currently_using_the_map(w http.ResponseWriter, r *http.Request) {

	var Url = fmt.Sprintf("https://css-open-platform.pudutech.com/pudu-entry/map-service/v1/open/point")

	const HTTPMethod = "GET"

	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	Host := u.Hostname()
	Path := u.Path
	Query := u.RawQuery

	Path = strings.TrimPrefix(Path, "/release")
	Path = strings.TrimPrefix(Path, "/test")
	Path = strings.TrimPrefix(Path, "/prepub")
	if Path == "" {
		Path = "/"
	}

	if len(Query) > 0 {
		args, _ := url.ParseQuery(Query)
		var keys []string
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sortQuery := ""
		for _, k := range keys {
			if args[k][0] != "" {
				sortQuery += "&" + k + "=" + args[k][0]
			} else {
				sortQuery += "&" + k
			}
		}
		sortQuery = strings.TrimPrefix(sortQuery, "&")
		Path = Path + "?" + sortQuery
	}

	xDate := time.Now().UTC().Format(GmtFormat)

	ContentMD5 := ""
	bodyStr := ``
	if HTTPMethod == "POST" {
		h := md5.New()
		h.Write([]byte(bodyStr))
		md5Str := hex.EncodeToString(h.Sum(nil))
		ContentMD5 = base64.StdEncoding.EncodeToString([]byte(md5Str))
	}

	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)

	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(bodyStr))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func maplist(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with your real API endpoint

	var Url = fmt.Sprintf("https://css-open-platform.pudutech.com/pudu-entry/map-service/v1/open/current?sn=%s&need_element=true", sn)

	const HTTPMethod = "GET"

	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	Host := u.Hostname()
	Path := u.Path
	Query := u.RawQuery

	Path = strings.TrimPrefix(Path, "/release")
	Path = strings.TrimPrefix(Path, "/test")
	Path = strings.TrimPrefix(Path, "/prepub")
	if Path == "" {
		Path = "/"
	}

	if len(Query) > 0 {
		args, _ := url.ParseQuery(Query)
		var keys []string
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sortQuery := ""
		for _, k := range keys {
			if args[k][0] != "" {
				sortQuery += "&" + k + "=" + args[k][0]
			} else {
				sortQuery += "&" + k
			}
		}
		sortQuery = strings.TrimPrefix(sortQuery, "&")
		Path = Path + "?" + sortQuery
	}

	xDate := time.Now().UTC().Format(GmtFormat)

	ContentMD5 := ""
	bodyStr := ``
	if HTTPMethod == "POST" {
		h := md5.New()
		h.Write([]byte(bodyStr))
		md5Str := hex.EncodeToString(h.Sum(nil))
		ContentMD5 = base64.StdEncoding.EncodeToString([]byte(md5Str))
	}

	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)

	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(bodyStr))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func chackapi(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with a real PuduOpen platform fixed domain
	var Url = fmt.Sprintf("https://css-open-platform.pudutech.com/pudu-entry/map-service/v1/open/point?sn=%s&limit=10&offset=0", sn)
	Url = strings.ReplaceAll(Url, "${b}", encode("2"))
	Url = strings.ReplaceAll(Url, "${a}", encode("###特殊字符测试"))
	Url = strings.ReplaceAll(Url, "${c}", encode("3"))

	const HTTPMethod = "GET"

	// Parse the URL to get Host and Path
	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	Host := u.Hostname()
	Path := u.Path
	Query := u.RawQuery

	// Remove environment prefix from path
	Path = strings.TrimPrefix(Path, "/release")
	Path = strings.TrimPrefix(Path, "/test")
	Path = strings.TrimPrefix(Path, "/prepub")
	if Path == "" {
		Path = "/"
	}

	// Sort query parameters
	if len(Query) > 0 {
		args, _ := url.ParseQuery(Query)
		var keys []string
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		sortQuery := ""
		for _, k := range keys {
			if args[k][0] != "" {
				sortQuery += "&" + k + "=" + args[k][0]
			} else {
				sortQuery += "&" + k
			}
		}
		sortQuery = strings.TrimPrefix(sortQuery, "&")
		Path = Path + "?" + sortQuery
	}

	// Get current UTC time
	xDate := time.Now().UTC().Format(GmtFormat)

	ContentMD5 := ""
	bodyStr := ``

	if HTTPMethod == "POST" {
		h := md5.New()
		h.Write([]byte(bodyStr))
		md5Str := hex.EncodeToString(h.Sum(nil))
		ContentMD5 = base64.StdEncoding.EncodeToString([]byte(md5Str))
	}

	// Construct the signing string
	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)

	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	// Construct the request headers
	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	// Send the request
	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(bodyStr))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	// Respond with the API result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func encode(s string) string {
	// Implement the encoding logic here
	return url.QueryEscape(s)
}
func report_the_location(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with your real API endpoint
	const Url = "https://css-open-platform.pudutech.com/pudu-entry/open-platform-service/v1/position_command"

	const HTTPMethod = "POST"

	// Define the JSON body
	body := fmt.Sprintf(`{
		"sn":"%s",
		"payload":{
			"interval":3,
			"times":10
		}
	}`, sn)

	// Parse the URL to get Host and Path
	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	Host := u.Hostname()
	Path := u.Path
	//

	// Get current UTC time
	xDate := time.Now().UTC().Format(GmtFormat)

	// Calculate Content-MD5
	h := md5.New()
	h.Write([]byte(body))
	md5Str := hex.EncodeToString(h.Sum(nil))
	ContentMD5 := base64.StdEncoding.EncodeToString([]byte(md5Str))

	// Construct the signing string
	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)
	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	// Construct the request headers
	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	// Send the request
	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	// Respond with the API result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func addjob1(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with your real API endpoint
	const Url = "https://css-open-platform.pudutech.com/pudu-entry/open-platform-service/v1/delivery_task"

	const HTTPMethod = "POST"

	// Define the JSON body
	body := fmt.Sprintf(`{
		"sn":"%s",
		"payload":{
			"type":"NEW",
			"delivery_sort":"AUTO",
			"execute_task": true,
			"trays":[
				{
					"destinations":[
					{
							"points":"%s",
							"id":"1111"
						}
					]
				},
				{
					"destinations":[
					{
							"points":"%s",
							"id":"1112"
						}
					]
				},
				{
					"destinations":[
					{
							"points":"%s",
							"id":"1113"
						}
				},
				{
					"destinations":[
					{
							"points":"%s",
							"id":"1114"
					}
			}
			]
		}
	}`, sn, ponit1, ponit2 ,ponit3,ponit4)

	// Parse the URL to get Host and Path
	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	Host := u.Hostname()
	Path := u.Path
	//

	// Get current UTC time
	xDate := time.Now().UTC().Format(GmtFormat)

	// Calculate Content-MD5
	h := md5.New()
	h.Write([]byte(body))
	md5Str := hex.EncodeToString(h.Sum(nil))
	ContentMD5 := base64.StdEncoding.EncodeToString([]byte(md5Str))

	// Construct the signing string
	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)
	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	// Construct the request headers
	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	// Send the request
	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	// Respond with the API result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}
func addjob2(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with your real API endpoint
	const Url = "https://css-open-platform.pudutech.com/pudu-entry/open-platform-service/v1/delivery_task"

	const HTTPMethod = "POST"

	// Define the JSON body
	body := fmt.Sprintf(`{
		"sn":"%s",
		"payload":{
			"type":"NEW",
			"delivery_sort":"AUTO",
			"execute_task": true,
			"trays":[
				{
					"destinations":[
					  {
					    "points":"%s",
						"id":"1111"
						}
					]
				},
				{
					"destinations":[
						{
							"points":"%s",
							"id":"1112"
						}
					]
				},
				{
					"destinations":[
						{
							"points":"%s",
							"id":"1113"
						}
					]
				}

			]
		}
		
		
	}`, sn, ponit1, ponit2, ponit3)

	// Parse the URL to get Host and Path
	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	Host := u.Hostname()
	Path := u.Path
	//

	// Get current UTC time
	xDate := time.Now().UTC().Format(GmtFormat)

	// Calculate Content-MD5
	h := md5.New()
	h.Write([]byte(body))
	md5Str := hex.EncodeToString(h.Sum(nil))
	ContentMD5 := base64.StdEncoding.EncodeToString([]byte(md5Str))

	// Construct the signing string
	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)
	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	// Construct the request headers
	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	// Send the request
	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	// Respond with the API result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

// api call
// https://css-open-platform.pudutech.com/pudu-entry/map-service/v1/open/point?sn=826094814050002&limit=10&offset=0
// use method post
func call(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with your real API endpoint
	const Url = "https://css-open-platform.pudutech.com/pudu-entry/open-platform-service/v1/custom_call"

	const HTTPMethod = "POST"

	// Define the JSON body
	body := fmt.Sprintf(`{
		"sn": "%s",
		"map_name": "%s",
		"point": "test1",
		"point_type": "table",
		"call_device_name": "appKey",
		"call_mode": "Empty"
		}`, sn, mapData)

	// Parse the URL to get Host and Path
	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	Host := u.Hostname()
	Path := u.Path
	//

	// Get current UTC time
	xDate := time.Now().UTC().Format(GmtFormat)

	// Calculate Content-MD5
	h := md5.New()
	h.Write([]byte(body))
	md5Str := hex.EncodeToString(h.Sum(nil))
	ContentMD5 := base64.StdEncoding.EncodeToString([]byte(md5Str))

	// Construct the signing string
	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)
	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	// Construct the request headers
	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	// Send the request
	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	// Respond with the API result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func sandtaskjob10s(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with your real API endpoint
	const Url = "https://css-open-platform.pudutech.com/pudu-entry/open-platform-service/v1/transport_task"

	const HTTPMethod = "POST"

	// Define the JSON body
	body := fmt.Sprintf(`{
		"sn":"%s",
		"payload":{
	    	"task_id":"11111111111111",
			"type":"NEW",
			"delivery_sort":"AUTO",
			"execute_task": true,
			"start_point": {
				"description":"Re",
				"content_type":"TEXT",
				"content_data":"test"
			},
			"start_wait_time": 10,
			"end_wait_time": 10,
			"task_remark": "WHATISTHIS",
			"proirity": 1,
			"trays":[
				{
					"destinations":[
					  {
						"points":"%s",
						"id":"1111",
						"name":"1",
						"amount":1,
						"content_type":"TEXT",
						"content":"test1",
						"trayIndex":1
						}
					]
				},
				{
					"destinations":[
						{
						"points":"%s",
						"id":"1112",
						"name":"2",
						"amount":1,
						"content_type":"TEXT",
						"content":"test2",
						"trayIndex":2
						}
					]
				},
				{
					"destinations":[
						{
						"points":"%s",
						"id":"1113",
						"name":"3",
						"amount":1,
						"content_type":"TEXT",
						"content":"test3",
						"trayIndex":3
						}
					]
				}
			]
		}
	}`, sn, ponit1, ponit2, ponit3)

	// Parse the URL to get Host and Path
	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	Host := u.Hostname()
	Path := u.Path
	//

	// Get current UTC time
	xDate := time.Now().UTC().Format(GmtFormat)

	// Calculate Content-MD5
	h := md5.New()
	h.Write([]byte(body))
	md5Str := hex.EncodeToString(h.Sum(nil))
	ContentMD5 := base64.StdEncoding.EncodeToString([]byte(md5Str))

	// Construct the signing string
	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)
	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	// Construct the request headers
	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	// Send the request
	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	// Respond with the API result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func sandtaskjob20s(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with your real API endpoint
	const Url = "https://css-open-platform.pudutech.com/pudu-entry/open-platform-service/v1/transport_task"

	const HTTPMethod = "POST"

	// Define the JSON body
	body := fmt.Sprintf(`{
		"sn":"%s",
		"payload":{
	    	"task_id":"11111111111111",
			"type":"NEW",
			"delivery_sort":"AUTO",
			"execute_task": true,
			"start_point": {
				"description":"Re",
				"content_type":"TEXT",
				"content":"test"
			},
			"start_wait_time": 10,
			"end_wait_time": 10,
			"task_remark": "WHATISTHIS",
			"proirity": 1,
			"trays":[
				{
					"destinations":[
					  {
						"points":"%s",
						"id":"1111",
						"name":"1",
						"amount":1,
						"content_type":"TEXT",
						"content":"test1",
						"trayIndex":1
						}
					]
				},
				{
					"destinations":[
						{
						"points":"%s",
						"id":"1112",
						"name":"2",
						"amount":1,
						"content_type":"TEXT",
						"content":"test2",
						"trayIndex":2
						}
					]
				},
				{
					"destinations":[
						{
						"points":"%s",
						"id":"1113",
						"name":"3",
						"amount":1,
						"content_type":"TEXT",
						"content":"test3",
						"trayIndex":3
						}
					]
				}
			]
		}
	}`, sn, ponit1, ponit2, ponit3)

	// Parse the URL to get Host and Path
	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	Host := u.Hostname()
	Path := u.Path
	//

	// Get current UTC time
	xDate := time.Now().UTC().Format(GmtFormat)

	// Calculate Content-MD5
	h := md5.New()
	h.Write([]byte(body))
	md5Str := hex.EncodeToString(h.Sum(nil))
	ContentMD5 := base64.StdEncoding.EncodeToString([]byte(md5Str))

	// Construct the signing string
	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)
	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	// Construct the request headers
	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	// Send the request
	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	// Respond with the API result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func wheretherobot(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with your real API endpoint
	const Url = "https://css-open-platform.pudutech.com/pudu-entry/open-platform-service/v1/transport_task"

	const HTTPMethod = "POST"

	// Define the JSON body
	body := fmt.Sprintf(`{
		"sn": "%s",
		"payload":{
			"interval":3,
			"time": 10
	}
	}`, sn)

	// Parse the URL to get Host and Path
	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	Host := u.Hostname()
	Path := u.Path
	//

	// Get current UTC time
	xDate := time.Now().UTC().Format(GmtFormat)

	// Calculate Content-MD5
	h := md5.New()
	h.Write([]byte(body))
	md5Str := hex.EncodeToString(h.Sum(nil))
	ContentMD5 := base64.StdEncoding.EncodeToString([]byte(md5Str))

	// Construct the signing string
	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)
	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	// Construct the request headers
	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	// Send the request
	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	// Respond with the API result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func cancelthetask(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with your real API endpoint
	const Url = "https://css-open-platform.pudutech.com/pudu-entry/open-platform-service/v1/cancel_task"
	const HTTPMethod = "POST"

	// Define the JSON body
	body := fmt.Sprintf(`{
		"sn": "%s",
		"payload":{
			"tasks":[{
				"name":"name",
				"type":"type"
			}]
		}
	}`, sn)

	// Parse the URL to get Host and Path
	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	Host := u.Hostname()
	Path := u.Path
	//

	// Get current UTC time
	xDate := time.Now().UTC().Format(GmtFormat)

	// Calculate Content-MD5
	h := md5.New()
	h.Write([]byte(body))
	md5Str := hex.EncodeToString(h.Sum(nil))
	ContentMD5 := base64.StdEncoding.EncodeToString([]byte(md5Str))

	// Construct the signing string
	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)
	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	// Construct the request headers
	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	// Send the request
	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	// Respond with the API result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

func formuratatestcase(w http.ResponseWriter, r *http.Request) {

	// URL - Replace with your real API endpoint
	const Url = "https://css-open-platform.pudutech.com/pudu-entry/open-platform-service/v1/transport_task"

	const HTTPMethod = "POST"

	// Define the JSON body
	body := fmt.Sprintf(`{
			"sn":"%s",
			"payload":{
				"task_id":"11111111111111",
				"type":"NEW",
				"delivery_sort":"AUTO",
				"execute_task": true,
				"start_point": {
					"destination":"A1_D"
				},
				"trays":[
					{
						"destinations":[
							{
								"points":"B2_D",
								"id":"1111",
								"name":"B2_D"
							}
						]
					}
				]
			}
		}`, sn)
	// Parse the URL to get Host and Path
	u, err := url.Parse(Url)
	if err != nil {
		http.Error(w, "Failed to parse URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	Host := u.Hostname()
	Path := u.Path
	//

	// Get current UTC time
	xDate := time.Now().UTC().Format(GmtFormat)

	// Calculate Content-MD5
	h := md5.New()
	h.Write([]byte(body))
	md5Str := hex.EncodeToString(h.Sum(nil))
	ContentMD5 := base64.StdEncoding.EncodeToString([]byte(md5Str))

	// Construct the signing string
	signingStr := fmt.Sprintf("x-date: %s\n%s\n%s\n%s\n%s\n%s", xDate, HTTPMethod, Accept, ContentType, ContentMD5, Path)
	mac := hmac.New(sha1.New, []byte(ApiAppSecret))
	_, err = mac.Write([]byte(signingStr))
	if err != nil {
		http.Error(w, "Failed to sign request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	sign := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"%s\"", ApiAppKey, signature)

	// Construct the request headers
	headers := map[string]string{
		"Host":          Host,
		"Accept":        Accept,
		"Content-Type":  ContentType,
		"x-date":        xDate,
		"Authorization": sign,
	}

	// Send the request
	req, err := http.NewRequest(HTTPMethod, Url, strings.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)

	// Respond with the API result
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

// Middleware to handle CORS
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-date")

		// Handle preflight request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next(w, r)
	}
}
