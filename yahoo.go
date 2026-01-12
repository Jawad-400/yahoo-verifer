package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type CheckRequest struct {
	Email string `json:"email"`
}

type CheckResponse struct {
	Email   string `json:"email"`
	Exists  bool   `json:"exists"`
	Message string `json:"message"`
}

// Global session management
var (
	jar        *cookiejar.Jar
	client     *http.Client
	acrumb     string
	crumb      string
	sessionIdx string
	lastSync   time.Time
)

func init() {
	var err error
	jar, err = cookiejar.New(nil)
	if err != nil {
		log.Fatal("Failed to create cookie jar:", err)
	}
	client = &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}
}

// Refresh session: GET create page → capture cookies automatically → extract real crumbs
func refreshYahooSession() error {
	fmt.Println("🔄 Refreshing Yahoo session & cookies...")

	createURL := "https://login.yahoo.com/account/create?src=ym-oasis&pspid=1197802296&activity=new-yahoo-account&ncid=100003073&.done=https%3A%2F%2Fmail.yahoo.com%3Fsrc%3Dym-oasis%26activity%3Dnew-yahoo-account%26autoAddImapIn%3Dtrue%26ncid%3D100003073"

	req, err := http.NewRequest("GET", createURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	html := string(body)

	// Extract hidden input values
	reAcrumb := regexp.MustCompile(`name=["']acrumb["'][^>]*value=["']([^"']+)["']`)
	reCrumb := regexp.MustCompile(`name=["']crumb["'][^>]*value=["']([^"']+)["']`)
	reSess := regexp.MustCompile(`name=["']sessionIndex["'][^>]*value=["']([^"']+)["']`)

	if m := reAcrumb.FindStringSubmatch(html); len(m) > 1 {
		acrumb = m[1]
	}
	if m := reCrumb.FindStringSubmatch(html); len(m) > 1 {
		crumb = m[1]
	}
	if m := reSess.FindStringSubmatch(html); len(m) > 1 {
		sessionIdx = m[1]
	}

	// If not found in hidden inputs, look for JSON in script tags
	if acrumb == "" || crumb == "" {
		reJSON := regexp.MustCompile(`"acrumb":"([^"]+)"|"crumb":"([^"]+)"|"sessionIndex":"([^"]+)"`)
		matches := reJSON.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if len(m) > 1 && m[1] != "" {
				acrumb = m[1]
			}
			if len(m) > 2 && m[2] != "" {
				crumb = m[2]
			}
			if len(m) > 3 && m[3] != "" {
				sessionIdx = m[3]
			}
		}
	}

	u, err := url.Parse("https://login.yahoo.com")
	if err != nil {
		log.Printf("Failed to parse URL for cookie count: %v", err)
		u = &url.URL{Host: "login.yahoo.com"} // fallback
	}

	fmt.Printf("✅ Session refreshed | Cookies: %d | acrumb: %s | crumb: %s | sessionIdx: %s\n",
		len(jar.Cookies(u)),
		acrumb[:min(8, len(acrumb))]+"...",
		crumb[:min(8, len(crumb))]+"...",
		sessionIdx[:min(8, len(sessionIdx))]+"...")
	lastSync = time.Now()
	return nil
}

func ensureFreshSession() error {
	if lastSync.IsZero() || time.Since(lastSync) > 5*time.Minute {
		return refreshYahooSession()
	}
	return nil
}

func CheckEmail(email string) (bool, string, error) {
	if err := ensureFreshSession(); err != nil {
		return false, "", err
	}

	// Clean email
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@yahoo.com") {
		email += "@yahoo.com"
	}
	username := strings.Split(email, "@")[0]

	validateURL := "https://login.yahoo.com/account/create/validate?src=ym-oasis&pspid=1197802296&activity=new-yahoo-account&ncid=100003073&.done=https%3A%2F%2Fmail.yahoo.com%3Fsrc%3Dym-oasis%26activity%3Dnew-yahoo-account%26autoAddImapIn%3Dtrue%26ncid%3D100003073&validateField=userId"

	form := url.Values{
		"sessionIndex": {sessionIdx},
		"acrumb":       {acrumb},
		"crumb":        {crumb},
		"specId":       {"yidregsimplified"},
		"context":      {"REGISTRATION"},
		"yidDomain":    {"yahoo.com"},
		"userId":       {username},
		"firstName":    {""},
		"lastName":     {""},
		"password":     {""},
		"mm":           {""},
		"dd":           {""},
		"yyyy":         {""},
		"tos0":         {"oath_freereg|us|en-US"},
	}

	req, err := http.NewRequest("POST", validateURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://login.yahoo.com")
	req.Header.Set("Referer", "https://login.yahoo.com/account/create?src=ym-oasis&pspid=1197802296&activity=new-yahoo-account&ncid=100003073&.done=https%3A%2F%2Fmail.yahoo.com%3Fsrc%3Dym-oasis%26activity%3Dnew-yahoo-account%26autoAddImapIn%3Dtrue%26ncid%3D100003073")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	respStr := string(body)

	// Auto-refresh on block or invalid crumb
	if resp.StatusCode >= 400 || strings.Contains(respStr, "blocked") || strings.Contains(respStr, "invalid") || strings.Contains(respStr, "crumb") {
		log.Printf("Blocked (status %d) → refreshing session...", resp.StatusCode)
		refreshYahooSession()
		return CheckEmail(email) // retry once
	}

	fmt.Printf("Response: %s\n", respStr[:min(500, len(respStr))])

	if strings.Contains(respStr, "IDENTIFIER_EXISTS") || strings.Contains(strings.ToLower(respStr), "taken") || strings.Contains(strings.ToLower(respStr), "unavailable") {
		return true, fmt.Sprintf("✅ EXISTS: %s is taken on Yahoo", email), nil
	}

	return false, fmt.Sprintf("❌ FREE: %s is available on Yahoo", email), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func checkEmailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		http.Error(w, `{"error": "Email required"}`, http.StatusBadRequest)
		return
	}

	log.Printf("Checking: %s", req.Email)

	exists, message, err := CheckEmail(req.Email)

	response := CheckResponse{
		Email:   req.Email,
		Exists:  exists,
		Message: message,
	}

	if err != nil {
		response.Message = "Error: " + err.Error()
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func main() {
	fmt.Println("🚀 Yahoo Email Checker - FULL AUTO COOKIE & SESSION")
	fmt.Println("====================================================")
	fmt.Println("Cookies auto-managed | Crumbs auto-extracted")
	fmt.Println("Server ready at http://localhost:8081/check")
	fmt.Println("")

	// Initial session
	if err := refreshYahooSession(); err != nil {
		log.Printf("Initial session warning: %v", err)
	}

	http.HandleFunc("/check", checkEmailHandler)
	log.Fatal(http.ListenAndServe(":8081", nil))
}
