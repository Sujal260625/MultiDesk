package store_test

import (
	"context"
	"testing"
	"time"

	"muiltdesk/server/internal/store"
)

func TestMemoryStoreAccounts(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryStore()
	defer s.Close()

	// 1. Create account
	err := s.CreateAccount(ctx, "usr-1", "alice@example.com", "Alice", []byte("hash-12345678901234567890123456789012"))
	if err != nil {
		t.Fatalf("CreateAccount failed: %v", err)
	}

	// 2. Duplicate email should fail
	err = s.CreateAccount(ctx, "usr-2", "alice@example.com", "Alice Duplicate", []byte("hash-2"))
	if err != store.ErrConflict {
		t.Fatalf("expected ErrConflict, got: %v", err)
	}

	// 3. Get account
	acc, err := s.GetAccountByEmail(ctx, "alice@example.com")
	if err != nil || acc == nil || acc.ID != "usr-1" {
		t.Fatalf("GetAccountByEmail failed: %v, %v", err, acc)
	}

	// 4. Update Token Version
	if err := s.UpdateAccountVersion(ctx, "usr-1"); err != nil {
		t.Fatalf("UpdateAccountVersion failed: %v", err)
	}

	acc2, _ := s.GetAccountByID(ctx, "usr-1")
	if acc2.TokenVersion != 1 {
		t.Fatalf("expected TokenVersion=1, got %d", acc2.TokenVersion)
	}
}

func TestMemoryStoreDevicesAndSessions(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryStore()
	defer s.Close()

	_ = s.CreateAccount(ctx, "owner-1", "bob@example.com", "Bob", []byte("hash"))

	// Create device
	dev := &store.Device{
		ID:        "dev-1",
		Name:      "Office Workstation",
		OwnerID:   "owner-1",
		PublicKey: "pubkey-base64",
		OS:        "Windows 11",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.CreateDevice(ctx, dev); err != nil {
		t.Fatalf("CreateDevice failed: %v", err)
	}

	// List devices
	devs, err := s.ListDevicesByOwner(ctx, "owner-1")
	if err != nil || len(devs) != 1 {
		t.Fatalf("ListDevicesByOwner failed: %v, %v", err, devs)
	}

	// Create session
	sess := &store.Session{
		ID:             "sess-1",
		OperatorID:     "owner-1",
		SourceDeviceID: "dev-1",
		TargetDeviceID: "dev-2",
		State:          "pending",
		RequestedPerms: []string{"view", "mouse"},
		Epoch:          1,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	sessRet, err := s.GetSession(ctx, "sess-1")
	if err != nil || sessRet.State != "pending" {
		t.Fatalf("GetSession failed: %v, %v", err, sessRet)
	}
}

func TestMemoryStorePresence(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryStore()
	defer s.Close()

	online, _ := s.IsOnline(ctx, "dev-x")
	if online {
		t.Fatalf("expected device to be offline")
	}

	_ = s.SetOnline(ctx, "dev-x", time.Minute)
	online, _ = s.IsOnline(ctx, "dev-x")
	if !online {
		t.Fatalf("expected device to be online after SetOnline")
	}
}
