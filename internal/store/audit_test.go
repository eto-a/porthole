// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAudit(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	if got, err := s.ListAudit(ctx, 10); err != nil || len(got) != 0 {
		t.Fatalf("empty log: %v, %v", got, err)
	}
	for i, action := range []string{"client.disconnect", "tunnel.close", "token.revoke"} {
		e := &AuditEntry{
			At: base.Add(time.Duration(i) * time.Second), Actor: "socket", Action: action,
			Target: "t" + action, Args: `{"remote":"1.2.3.4"}`, Result: "ok",
		}
		if err := s.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
		if e.ID != int64(i+1) {
			t.Errorf("entry %d got id %d", i, e.ID)
		}
	}

	got, err := s.ListAudit(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Action != "token.revoke" || got[1].Action != "tunnel.close" {
		t.Fatalf("newest first, limit 2: %+v", got)
	}
	if !got[0].At.Equal(base.Add(2*time.Second)) || got[0].Actor != "socket" || got[0].Args != `{"remote":"1.2.3.4"}` || got[0].Result != "ok" {
		t.Errorf("fields did not round-trip: %+v", got[0])
	}
	if all, err := s.ListAudit(ctx, 0); err != nil || len(all) != 3 {
		t.Errorf("limit 0 should use the default: %d entries, %v", len(all), err)
	}
}

func TestAuditTruncatesLongFields(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	e := &AuditEntry{At: time.Now(), Actor: "a", Action: "x", Target: strings.Repeat("я", 2000), Args: strings.Repeat("a", 10000)}
	if err := s.AppendAudit(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListAudit(ctx, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v, %v", got, err)
	}
	if len(got[0].Target) > maxFieldLen || len(got[0].Args) != maxAuditArgsLen {
		t.Errorf("target %d bytes, args %d bytes", len(got[0].Target), len(got[0].Args))
	}
	for _, r := range got[0].Target {
		if r == '�' {
			t.Fatal("truncation split a UTF-8 sequence")
		}
	}
}
