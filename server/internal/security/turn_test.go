package security

import (
	"testing"
	"time"
)

func TestTURNRESTCredentialInteroperability(t *testing.T) {
	// Expected value was independently calculated with Python's hmac/sha1.
	user, password := TURNCredential("test-shared-secret", "operator", time.Unix(1700000600, 0))
	if user != "1700000600:operator" || password != "pUute+HhhZOwDL1rzB39MmIgWKs=" {
		t.Fatalf("unexpected TURN REST credentials: %s %s", user, password)
	}
	otherUser, otherPassword := TURNCredential("test-shared-secret", "other", time.Unix(1700000600, 0))
	if otherUser == user || otherPassword == password {
		t.Fatal("relay credentials are not scoped to the account")
	}
}
