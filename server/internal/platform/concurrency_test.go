package platform

import (
	"net/http/httptest"
	"sync"
	"testing"
)

func TestConcurrentAuthenticatedReads(t *testing.T) {
	f := setup(t)
	token := f.s.signAccess("operator")
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("GET", "/v1/devices", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			f.h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Errorf("read failed: %d", w.Code)
			}
		}()
	}
	wg.Wait()
}
func TestLogoutInvalidatesAccessToken(t *testing.T) {
	f := setup(t)
	token := f.s.signAccess("operator")
	w := f.call(t, "POST", "/v1/auth/logout", "operator", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if _, err := f.s.verifyAccess(token); err == nil {
		t.Fatal("logged-out access token remained valid")
	}
}
