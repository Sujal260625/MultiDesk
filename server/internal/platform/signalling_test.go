package platform

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/coder/websocket"
	"muiltdesk/server/internal/security"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNativeSignallingRenewalIsBoundToAccount(t *testing.T) {
	f := setup(t)
	delete(f.s.peers, "source")
	nonce := randomID(24)
	f.s.challenges[nonce] = challenge{"operator", f.s.now().Add(time.Minute)}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+f.s.signAccess("operator"))
	headers.Set("X-Device-ID", "source")
	headers.Set("X-Device-Nonce", nonce)
	headers.Set("X-Device-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(f.sourceKey, security.DeviceMessage("GET", "/v1/signalling", nonce))))
	server := httptest.NewServer(f.h)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/v1/signalling", &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	renew := func(user string) {
		f.s.mu.Lock()
		token := f.s.signAccess(user)
		f.s.mu.Unlock()
		body, _ := json.Marshal(map[string]any{"type": "auth.refresh", "payload": map[string]string{"access_token": token}})
		if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
			t.Fatal(err)
		}
	}
	renew("operator")
	_, raw, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var event Signal
	if json.Unmarshal(raw, &event) != nil || event.Type != "auth.renewed" {
		t.Fatalf("unexpected acknowledgement: %s", raw)
	}
	renew("stranger")
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("signalling account takeover accepted")
	}
}
