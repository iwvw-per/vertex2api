package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bsfdsagfadg/vertex/internal/recaptcha"
	"github.com/bsfdsagfadg/vertex/internal/transport"
)

const (
	batchURL = "https://cloudconsole-pa.clients6.google.com/v3/entityServices/AiplatformEntityService/schemas/AIPLATFORM_GRAPHQL:batchGraphql?key=AIzaSyCI-zsRP85UVOi0DjtiCwWBwQ1djDy741g&prettyPrint=false"
	querySig  = "2/l8eCsMMY49imcDQ/lwwXyL8cYtTjxZBF2dNqy69LodY="
)

func buildBody(model, token string) map[string]any {
	digits := make([]byte, 16)
	for i := range digits {
		digits[i] = '0' + byte(rand.IntN(10))
	}
	return map[string]any{
		"requestContext": map[string]any{
			"clientVersion":    "boq_cloud-boq-clientweb-vertexaistudio_20260630.00_p0",
			"pagePath":         "/agent-platform/studio/multimodal",
			"pageViewId":       1000000000000000 + rand.Int64N(8000000000000000),
			"trackingId":       "d" + string(digits),
			"backendOverrides": map[string]any{},
			"clientSessionId":  "",
			"selectedPurview":  map[string]any{},
			"jurisdiction":     "global",
			"localizationData": map[string]string{"locale": "zh_CN", "timezone": "Asia/Hong_Kong"},
		},
		"querySignature": querySig,
		"operationName":  "StreamGenerateContentAnonymous",
		"variables": map[string]any{
			"model":            model,
			"region":           "global",
			"contents":         []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "hi"}}}},
			"generationConfig": map[string]any{"maxOutputTokens": 8},
			"recaptchaToken":   token,
		},
	}
}

var (
	tokenCache   = map[string]string{}
	tokenCacheMu sync.Mutex
	net          = transport.NewNetworkClient(false)
)

func tokenFor(ctx context.Context, uri string) string {
	tokenCacheMu.Lock()
	if t, ok := tokenCache[uri]; ok {
		tokenCacheMu.Unlock()
		return t
	}
	tokenCacheMu.Unlock()

	sess, err := net.CreateSession(15, uri, "probe")
	if err != nil {
		return ""
	}
	tok, err := recaptcha.FetchRecaptchaTokenWithSession(ctx, sess)
	sess.Close()
	if err != nil || tok == "" {
		return ""
	}
	tokenCacheMu.Lock()
	tokenCache[uri] = tok
	tokenCacheMu.Unlock()
	return tok
}

func probeOne(model string, uri string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	token := tokenFor(ctx, uri)
	if token == "" {
		return "AUTH"
	}
	sess, err := net.CreateSession(20, uri, "probe")
	if err != nil {
		return "ERR"
	}
	body, _ := json.Marshal(buildBody(model, token))
	header := transport.XHRHeaders("application/json", "*/*",
		"https://console.cloud.google.com", "https://console.cloud.google.com/", "cross-site")
	status, data, err := sess.DoAndRead(ctx, "POST", batchURL, header, strings.NewReader(string(body)))
	sess.Close()
	if err != nil {
		return "ERR"
	}
	txt := string(data)
	switch {
	case strings.Contains(txt, "not found") || strings.Contains(txt, "Publisher model") || status == 404:
		return "INVALID"
	case strings.Contains(txt, "quota") || strings.Contains(txt, "exhausted") || strings.Contains(txt, "429"):
		return "LIMITED"
	case strings.Contains(txt, "Failed to verify") || strings.Contains(txt, "permission"):
		return "AUTH"
	case status == 200 && strings.Contains(txt, "streamGenerateContentAnonymous"):
		return "VALID"
	default:
		return "HTTP" + fmt.Sprint(status)
	}
}

func main() {
	modelsFile := "config/models.json"
	if len(os.Args) > 1 {
		modelsFile = os.Args[1]
	}
	nodes := strings.FieldsFunc(os.Getenv("VPROXY_NODES"), func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '|' || r == '\n'
	})
	var all []string
	for _, n := range nodes {
		if n != "" {
			all = append(all, n)
		}
	}
	if len(all) == 0 {
		fmt.Println("no nodes provided via VPROXY_NODES")
		os.Exit(1)
	}

	raw, err := os.ReadFile(modelsFile)
	if err != nil {
		fmt.Println("read models fail:", err)
		os.Exit(1)
	}
	var cfg struct {
		Models []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	_ = json.Unmarshal(raw, &cfg)

	fmt.Printf("models=%d nodes=%d start=%s\n", len(cfg.Models), len(all), time.Now().Format("15:04:05"))
	var mu sync.Mutex
	type row struct{ id, v string }
	var rows []row
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for _, m := range cfg.Models {
		wg.Add(1)
		go func(model string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rnd := rand.Perm(len(all))
			verdict := "UNKNOWN"
			for _, idx := range rnd[:min(4, len(rnd))] {
				v := probeOne(model, all[idx])
				verdict = v
				if v == "VALID" || v == "INVALID" || v == "LIMITED" {
					break
				}
			}
			mu.Lock()
			rows = append(rows, row{model, verdict})
			mu.Unlock()
			fmt.Fprintf(os.Stderr, "done %-36s %s\n", model, verdict)
		}(m.ID)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	lookup := map[string]string{}
	for _, r := range rows {
		lookup[r.id] = r.v
	}
	invalids := []string{}
	for _, m := range cfg.Models {
		v := lookup[m.ID]
		fmt.Printf("  %-36s %s\n", m.ID, v)
		if v == "INVALID" {
			invalids = append(invalids, m.ID)
		}
	}
	fmt.Println("INVALID_MODELS=" + strings.Join(invalids, ","))
	fmt.Println("finished=" + time.Now().Format("15:04:05"))
}