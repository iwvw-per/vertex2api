package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsfdsagfadg/vertex/internal/config"
	"github.com/bsfdsagfadg/vertex/internal/db"
	"github.com/bsfdsagfadg/vertex/internal/recaptcha"
	"github.com/bsfdsagfadg/vertex/internal/vertex"
)

// 验证模型列表只返回原始模型，不含 fake-/假流式- 变体。
func TestIntegrationModelsListHasNoFakeVariants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	fx := newTestServer(t)

	req, _ := http.NewRequest("GET", fx.server.URL+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	data, ok := body["data"].([]any)
	if !ok || len(data) == 0 {
		t.Fatal("data is empty")
	}

	var hasBase bool
	for _, item := range data {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		if strings.HasPrefix(id, "fake-") || strings.HasPrefix(id, "假流式-") {
			t.Fatalf("模型列表不应包含假流式变体: %q", id)
		}
		if id == "gemini-2.5-flash" {
			hasBase = true
		}
	}
	if !hasBase {
		t.Fatal("模型列表缺少原始模型 gemini-2.5-flash")
	}
}

// 验证非流式 chat 响应包含 usage（含 token 统计），源头是上游 usageMetadata 经 map 分支透传。
func TestIntegrationChatCompletionIncludesUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	fx := newTestServer(t)

	body := map[string]any{
		"model":    "gemini-2.5-flash",
		"messages": []any{map[string]any{"role": "user", "content": "Say hello"}},
		"stream":   false,
	}
	resp := doPost(t, fx.server.URL+"/v1/chat/completions", "sk-test-key", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	var oaiResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&oaiResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	usage, ok := oaiResp["usage"].(map[string]any)
	if !ok {
		t.Fatalf("响应缺少 usage 字段: %v", oaiResp)
	}
	if usage["prompt_tokens"] != float64(10) || usage["completion_tokens"] != float64(20) || usage["total_tokens"] != float64(30) {
		t.Fatalf("usage token 统计错误: %v", usage)
	}
}

// 验证 bug 修复：当 usageMetadata 位于 data 外层（与 ui 平级）时，map 分支不得丢弃它。
func TestIntegrationUsageMetadataOuterDataPreserved(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.AdminPassword = "test-admin-pw"
	cfg.ParallelPoolEnabled = false
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), cfgBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VPROXY_CONFIG", filepath.Join(dir, "config.json"))
	config.InvalidateCache()

	keysContent := "test:sk-test-key:Test Key\n"
	if err := os.WriteFile(filepath.Join(dir, "api_keys.txt"), []byte(keysContent), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VPROXY_API_KEYS", filepath.Join(dir, "api_keys.txt"))

	if err := db.InitDB(filepath.Join(dir, "test.db")); err != nil {
		t.Fatal(err)
	}

	// mock 上游：usageMetadata 与 ui 平级（位于 data 外层）
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		resp := fmt.Sprintf(`[{"results":[{"data":{"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":20,"totalTokenCount":30},"ui":{"streamGenerateContentAnonymous":%s}}}]}]`,
			`{"candidates":[{"content":{"parts":[{"text":"Hello! How can I help you today?"}],"role":"model"},"finishReason":"STOP"}]}`)
		_, _ = w.Write([]byte(resp))
	}))
	vertex.SetBatchGraphqlURL(mockUpstream.URL + "/batchGraphql?key=test&prettyPrint=false")

	mockPool := recaptcha.NewTokenPoolCustom(func(proxyURI string) (string, error) {
		return "test-recaptcha-token", nil
	})
	vc := vertex.NewVertexAIClient(config.StaticProvider(cfg))
	vc.SetTokenPool(mockPool)

	resetAdminSessions()
	keys := NewAPIKeyManager()
	keys.LoadKeys()

	srv := NewServer(vc, keys, config.StaticProvider(cfg))
	ts := httptest.NewServer(srv.Handler())
	defer func() {
		ts.Close()
		mockUpstream.Close()
		db.CloseDB()
		config.InvalidateCache()
	}()

	body := map[string]any{
		"model":    "gemini-2.5-flash",
		"messages": []any{map[string]any{"role": "user", "content": "Say hello"}},
		"stream":   false,
	}
	resp := doPost(t, ts.URL+"/v1/chat/completions", "sk-test-key", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200, body=%s", resp.StatusCode, readBodyForTest(resp))
	}

	var oaiResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&oaiResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	usage, ok := oaiResp["usage"].(map[string]any)
	if !ok {
		t.Fatalf("外层 usageMetadata 被丢弃，响应缺少 usage: %v", oaiResp)
	}
	if usage["prompt_tokens"] != float64(10) || usage["completion_tokens"] != float64(20) || usage["total_tokens"] != float64(30) {
		t.Fatalf("usage token 统计错误: %v", usage)
	}
}
func readBodyForTest(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}
