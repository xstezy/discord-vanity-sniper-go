package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/valyala/fasthttp"
	"golang.org/x/net/http2"
)

var (
	socket        *websocket.Conn
	mu            sync.Mutex
	sequence      int
	mfaToken      string
	mfaRetryCount int
	maxMfaRetries = 4
	guilds        = make(map[string]string)
	config        Config
	webhookURL    string

	fastHttpClient = &fasthttp.Client{
		TLSConfig: &tls.Config{
			InsecureSkipVerify:       true,
			MinVersion:               tls.VersionTLS13,
			MaxVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			CipherSuites:             []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP384, tls.CurveP521},
			KeyLogWriter:             nil,
			SessionTicketsDisabled:   true,
			VerifyConnection: func(state tls.ConnectionState) error {
				return nil
			},
		},
	}
)

const (
	DiscordGatewayURL = "wss://gateway.discord.gg"
	OpcodeDispatch    = 0
)

type Config struct {
	Token        string `json:"token"`
	SelfToken    string `json:"self"`
	Password     string `json:"password"`
	GuildID      string `json:"guild_id"`
	NewVanityURL string `json:"new_vanity_url"`
	WebhookURL   string `json:"webhook_url"`
}

type MFAPayload struct {
	Ticket string `json:"ticket"`
	Type   string `json:"mfa_type"`
	Data   string `json:"data"`
}

type MFAResponse struct {
	Token string `json:"token"`
}

type VanityResponse struct {
	MFA struct {
		Ticket string `json:"ticket"`
	} `json:"mfa"`
}

type GatewayPayload struct {
	Op int             `json:"op"`
	D  json.RawMessage `json:"d"`
	S  int             `json:"s,omitempty"`
	T  string          `json:"t,omitempty"`
}

func setCommonHeaders(req *fasthttp.Request, token string) {
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	if mfaToken != "" {
		req.Header.Set("X-Discord-Mfa-Authorization", mfaToken)
		req.Header.Set("Cookie", "__Secure-recent_mfa="+mfaToken)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x32) "+"AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9164 "+ "Chrome/124.0.6367.243 Electron/30.2.0 Safari/537.36")
	req.Header.Set("X-Super-Properties", "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MTY0Iiwib3NfdmVyc2lvbiI6IjEwLjAuMjI2MzEiLCJvc19hcmNoIjoieDY0IiwiYXBwX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoidHIiLCJicm93c2VyX3VzZXJfYWdlbnQiOiJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBkaXNjb3JkLzEuMC45MTY0IENocm9tZS8xMjQuMC42MzY3LjI0MyBFbGVjdHJvbi8zMC4yLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjMwLjIuMCIsIm9zX3Nka192ZXJzaW9uIjoiMjI2MzEiLCJjbGllbnRfdnVibF9udW1iZXIiOjUyODI2LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==")
	req.Header.Set("X-Discord-Timezone", "Europe/Istanbul")
	req.Header.Set("X-Discord-Locale", "en-US")
	req.Header.Set("X-Debug-Options", "bugReporterEnabled")
	req.Header.Set("Content-Type", "application/json")
}

func setCommonHeaders12(req *fasthttp.Request, token string) {
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x32) "+"AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9164 "+"Chrome/124.0.6367.243 Electron/30.2.0 Safari/537.36")
	req.Header.Set("X-Super-Properties", "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MTY0Iiwib3NfdmVyc2lvbiI6IjEwLjAuMjI2MzEiLCJvc19hcmNoIjoieDY0IiwiYXBwX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoidHIiLCJicm93c2VyX3VzZXJfYWdlbnQiOiJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBkaXNjb3JkLzEuMC45MTY0IENocm9tZS8xMjQuMC42MzY3LjI0MyBFbGVjdHJvbi8zMC4yLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjMwLjIuMCIsIm9zX3Nka192ZXJzaW9uIjoiMjI2MzEiLCJjbGllbnRfdnVibF9udW1iZXIiOjUyODI2LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==")
	req.Header.Set("X-Discord-Timezone", "Europe/Istanbul")
	req.Header.Set("X-Discord-Locale", "en-US")
	req.Header.Set("X-Debug-Options", "bugReporterEnabled")
	req.Header.Set("Content-Type", "application/json")
}
func setCommonHeaders13(req *http.Request, token string) {
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	if mfaToken != "" {
		req.Header.Set("X-Discord-Mfa-Authorization", mfaToken)
		req.Header.Set("Cookie", "__Secure-recent_mfa="+mfaToken)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x32) "+"AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9164 "+"Chrome/124.0.6367.243 Electron/30.2.0 Safari/537.36")
	req.Header.Set("X-Super-Properties", "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MTY0Iiwib3NfdmVyc2lvbiI6IjEwLjAuMjI2MzEiLCJvc19hcmNoIjoieDY0IiwiYXBwX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoidHIiLCJicm93c2VyX3VzZXJfYWdlbnQiOiJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBkaXNjb3JkLzEuMC45MTY0IENocm9tZS8xMjQuMC42MzY3LjI0MyBFbGVjdHJvbi8zMC4yLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjMwLjIuMCIsIm9zX3Nka192ZXJzaW9uIjoiMjI2MzEiLCJjbGllbnRfdnVibF9udW1iZXIiOjUyODI2LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==")
	req.Header.Set("X-Discord-Timezone", "Europe/Istanbul")
	req.Header.Set("X-Discord-Locale", "en-US")
	req.Header.Set("X-Debug-Options", "bugReporterEnabled")
	req.Header.Set("Content-Type", "application/json")
}
func sendWebhook(content, title, description string, color int) error {
	payload := map[string]interface{}{
		"content": content,
		"embeds": []map[string]interface{}{{
			"title":       title,
			"description": description,
			"color":       color,
		}},
	}

	jsonData, _ := json.Marshal(payload)
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(webhookURL)
	req.Header.SetMethod("POST")
	setCommonHeaders(req, "")
	req.SetBody(jsonData)

	return fastHttpClient.Do(req, resp)
}

func sendMFA(token, ticket, pass string) string {
	payload := MFAPayload{
		Ticket: ticket,
		Type:   "password",
		Data:   pass,
	}

	jsonPayload, _ := json.Marshal(payload)
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://canary.discord.com/api/v7/mfa/finish")
	req.Header.SetMethod("POST")
	setCommonHeaders(req, token)
	req.SetBody(jsonPayload)

	if err := fastHttpClient.Do(req, resp); err != nil {
		return "err"
	}

	if resp.StatusCode() == fasthttp.StatusOK {
		var mfaResponse MFAResponse
		if err := json.Unmarshal(resp.Body(), &mfaResponse); err != nil {
			return "err"
		}
		return mfaResponse.Token
	}
	return "err"
}

func getURL(token, guildID, newURL, pass string, once bool) {

	body := []byte("{\"code\":\"" + newURL + "\"}")

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	url := "https://discord.com/api/v9/guilds/" + guildID + "/vanity-url"
	req.SetRequestURI(url)
	req.Header.SetMethod("PATCH")
	setCommonHeaders(req, token)
	mu.Lock()
	currentMfaToken := mfaToken
	mu.Unlock()

	if currentMfaToken != "" {
		req.Header.Set("X-Discord-Mfa-Authorization", currentMfaToken)
		req.Header.Set("Cookie", "__Secure-recent_mfa="+currentMfaToken)
	}

	req.SetBody(body)
	err := fastHttpClient.Do(req, resp)
	if err != nil {
		fmt.Sprintf("Request failed: %v", err)
		return
	}

	bodyBytes := resp.Body()

	if resp.StatusCode() != fasthttp.StatusOK {
		if resp.StatusCode() == fasthttp.StatusUnauthorized {

			mu.Lock()
			if mfaRetryCount >= maxMfaRetries {
				mu.Unlock()
				return
			}
			mfaRetryCount++
			mu.Unlock()

			var vanityResponse VanityResponse
			err := json.Unmarshal(bodyBytes, &vanityResponse)
			if err != nil {
				fmt.Sprintf("Error unmarshalling vanity response: %s", err)
				return
			}
			ticket := vanityResponse.MFA.Ticket
			fmt.Sprintf("MFA Ticket: %s", ticket)
			newMfaToken := sendMFA(token, ticket, pass)
			if newMfaToken == "" || newMfaToken == "err" {
				return
			}
			mu.Lock()
			mfaToken = newMfaToken
			mu.Unlock()
			getURL(token, guildID, newURL, pass, false)

		} else {
			fmt.Sprintf("Request failed: %v - %s", err, string(bodyBytes))
		}
	} else {
		fmt.Sprintf("Claimed vanity: %s", newURL)
	}
}
func getURL1(token, guildID, find, pass string, once bool) {
	if find == "" {
		return
	}
	requestBody := []byte(`{"code":"` + find + `"}`)
	url := "https://canary.discord.com/api/v7/guilds/" + guildID + "/vanity-url"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	req, _ := http.NewRequest("PATCH", url, bytes.NewBuffer(requestBody))
	mu.Lock()
	currentMfaToken := mfaToken
	mu.Unlock()
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)  Safari/537.36")
	req.Header.Set("X-Super-Properties", "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MTY0Iiwib3NfdmVyc2lvbiI6IjEwLjAuMjI2MzEiLCJvc19hcmNoIjoieDY0IiwiYXBwX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoidHIiLCJicm93c2VyX3VzZXJfYWdlbnQiOiJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBkaXNjb3JkLzEuMC45MTY0IENocm9tZS8xMjQuMC42MzY3LjI0MyBFbGVjdHJvbi8zMC4yLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjMwLjIuMCIsIm9zX3Nka192ZXJzaW9uIjoiMjI2MzEiLCJjbGllbnRfdnVibF9udW1iZXIiOjUyODI2LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==")
	req.Header.Set("X-Discord-Mfa-Authorization", currentMfaToken)
	req.Header.Set("Cookie", "__Secure-recent_mfa="+currentMfaToken)
	resp, _ := client.Do(req)
	defer resp.Body.Close()

	sendWebhook("@everyone", "[REQ 1]", fmt.Sprintf("GUİLD-UPDATE-VANİTY: %s", find), 0xFFC0CB)
}
func getURL2(token, guildID, find, pass string, once bool) {
	if find == "" {
		return
	}
	requestBody := []byte(`{"code":"` + find + `"}`)
	url := "https://canary.discord.com/api/v7/guilds/" + guildID + "/vanity-url"
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest("PATCH", url, bytes.NewBuffer(requestBody))
	setCommonHeaders13(req, token)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	sendWebhook("@everyone", "[REQ 2]", fmt.Sprintf("GUİLD-UPDATE-VANİTY: %s", find), 0xFFC0CB)
}

func connectGateway() error {
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	var err error
	socket, _, err = dialer.Dial(DiscordGatewayURL, nil)
	return err
}

func handleMessages(token, guildID, newURL, pass string) {
	for {
		_, message, err := socket.ReadMessage()
		if err != nil {
			return
		}

		var payload GatewayPayload
		if err := json.Unmarshal(message, &payload); err != nil {
			continue
		}
		switch payload.Op {
		case OpcodeDispatch:
			handleDispatchEvent(payload, token, guildID, pass)
		}
		if payload.S != 0 {
			mu.Lock()
			sequence = payload.S
			mu.Unlock()
		}
	}
}
func handleDispatchEvent(payload GatewayPayload, token, guildID, pass string) {
	switch payload.T {
	case "READY":
		handleReadyEvent(payload)
	case "GUILD_UPDATE":
		handleGuildUpdateEvent(payload, token, guildID, pass)
	}
}
func handleReadyEvent(payload GatewayPayload) {
	var dataMap map[string]interface{}
	if err := json.Unmarshal(payload.D, &dataMap); err != nil {
		return
	}
	if guildList, ok := dataMap["guilds"].([]interface{}); ok {
		for _, guild := range guildList {
			processGuild(guild)
		}
	}
}
func processGuild(guild interface{}) {
	if guildMap, ok := guild.(map[string]interface{}); ok {
		if guildID, ok := guildMap["id"].(string); ok {
			if vanityURLCode, ok := guildMap["vanity_url_code"].(string); ok {
				guilds[guildID] = vanityURLCode
			}
		}
	}
}
func handleGuildUpdateEvent(payload GatewayPayload, token, guildID, pass string) {
	var dataMap map[string]interface{}
	if err := json.Unmarshal(payload.D, &dataMap); err != nil {
		return
	}

	guildIDxxd, _ := dataMap["guild_id"].(string)
	vanityURL, _ := dataMap["vanity_url_code"].(string)

	if currentVanityURL, exists := guilds[guildIDxxd]; exists && currentVanityURL != vanityURL {
		go getURL(token, guildID, currentVanityURL, pass, false)
		go getURL1(token, guildID, currentVanityURL, pass, false)
		go getURL2(token, guildID, currentVanityURL, pass, false)
	}
}

func identifyGateway(token string) error {
	identify := struct {
		Op int `json:"op"`
		D  struct {
			Token      string            `json:"token"`
			Intents    int               `json:"intents"`
			Properties map[string]string `json:"properties"`
		} `json:"d"`
	}{
		Op: 2,
		D: struct {
			Token      string            `json:"token"`
			Intents    int               `json:"intents"`
			Properties map[string]string `json:"properties"`
		}{
			Token:   token,
			Intents: 1 << 0,
			Properties: map[string]string{
				"$os":      "linux",
				"$browser": "go",
				"$device":  "go",
			},
		},
	}
	return socket.WriteJSON(identify)
}
func main() {
	fmt.Println("VANİTY SNİPER STATİNG...")

	data, err := os.ReadFile("config.json")
	if err != nil {
		fmt.Println("Config dosyası okunamadı:", err)
		return
	}

	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Println("Config dosyası çözülürken hata:", err)
		return
	}
	fmt.Println("UPLAOD CONFİG")

	webhookURL = config.WebhookURL

	if config.Token == "" || config.Password == "" || config.GuildID == "" || config.WebhookURL == "" || config.SelfToken == "" {
		fmt.Println("Config eksik veya hatalı. Tüm alanları doldurduğunuzdan emin olun.")
		return
	}

	body := []byte(`{"code":"` + config.NewVanityURL + `"}`)
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("https://canary.discord.com/api/v7/guilds/" + config.GuildID + "/vanity-url")
	req.Header.SetMethod("PATCH")
	setCommonHeaders12(req, config.Token)
	req.SetBody(body)

	if err := fastHttpClient.Do(req, resp); err == nil && resp.StatusCode() == fasthttp.StatusUnauthorized {
		var vanityResponse VanityResponse
		if err := json.Unmarshal(resp.Body(), &vanityResponse); err == nil {
			if newToken := sendMFA(config.Token, vanityResponse.MFA.Ticket, config.Password); newToken != "" && newToken != "err" {
				mfaToken = newToken
			}
		}
	}
	if err := connectGateway(); err != nil {
		fmt.Println("Gateway bağlantısı başarısız:", err)
		return
	}

	if err := identifyGateway(config.SelfToken); err != nil {
		fmt.Println("Gateway doğrulama başarısız:", err)
		return
	}
	fmt.Println("LOGİN ACC")
	go handleMessages(config.Token, config.GuildID, config.NewVanityURL, config.Password)
	fmt.Println("SNİPER STARTED")
	time.Sleep(40 * time.Second)
	os.Exit(0)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	fmt.Println("Program sonlandırılıyor.")
	if socket != nil {
		socket.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	}
}