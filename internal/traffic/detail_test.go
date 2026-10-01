// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package traffic

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func detailWith(body int) *Detail {
	return &Detail{
		RequestHeaders:  http.Header{"Authorization": {"Bearer s3cret"}, "Cookie": {"sid=1"}, "Accept": {"*/*"}, "Proxy-Authorization": {"x"}},
		ResponseHeaders: http.Header{"Set-Cookie": {"a=b", "c=d"}, "Content-Type": {"text/plain"}},
		RequestBody:     Body{Data: bytes.Repeat([]byte("a"), body), Size: int64(body)},
		Target:          "/x?api_key=SECRET",
	}
}

func TestDetailRedactsAndClips(t *testing.T) {
	q := NewRequests(10)
	d := detailWith(MaxBodyBytes + 100) // a caller that forgot to clip
	d.ResponseBody = Body{Data: []byte("ok"), Size: 2}
	id := q.Add(Request{Path: "/x", Detail: d})
	got, ok := q.Get(id)
	if !ok || got.Detail == nil || !got.HasDetail {
		t.Fatalf("no detail: %+v", got)
	}
	h := got.Detail
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
		if v := h.RequestHeaders[name]; len(v) != 1 || v[0] != Redacted {
			t.Errorf("%s = %v", name, v)
		}
	}
	if v := h.ResponseHeaders["Set-Cookie"]; len(v) != 1 || v[0] != Redacted {
		t.Errorf("Set-Cookie = %v", v)
	}
	if h.RequestHeaders.Get("Accept") != "*/*" || h.ResponseHeaders.Get("Content-Type") != "text/plain" {
		t.Errorf("harmless headers changed: %v %v", h.RequestHeaders, h.ResponseHeaders)
	}
	if len(h.RequestBody.Data) != MaxBodyBytes || !h.RequestBody.Truncated || h.RequestBody.Size != MaxBodyBytes+100 {
		t.Errorf("request body: %d bytes, truncated %v, size %d", len(h.RequestBody.Data), h.RequestBody.Truncated, h.RequestBody.Size)
	}
	// The caller's maps are untouched, and the query of the target stays raw for replay but is not serialised.
	if d.RequestHeaders.Get("Authorization") != "Bearer s3cret" {
		t.Error("Add modified the caller's headers")
	}
	if h.Target != "/x?api_key=SECRET" {
		t.Errorf("target %q", h.Target)
	}
	b, err := json.Marshal(got)
	if err != nil || strings.Contains(string(b), "s3cret") || strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "sid=1") {
		t.Errorf("json leaks a secret: %v %s", err, b[:min(len(b), 400)])
	}
}

func TestBodyJSON(t *testing.T) {
	for _, in := range []Body{
		{},
		{Data: []byte("héllo"), Size: 6},
		{Data: []byte{0xff, 0xfe, 0x00}, Size: 100, Truncated: true},
	} {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var out Body
		if err := json.Unmarshal(b, &out); err != nil || !bytes.Equal(out.Data, in.Data) || out.Size != in.Size || out.Truncated != in.Truncated {
			t.Errorf("%s -> %+v, %v", b, out, err)
		}
	}
	if b, _ := json.Marshal(Body{Data: []byte("text"), Size: 4}); !strings.Contains(string(b), `"text":"text"`) {
		t.Errorf("valid UTF-8 is not written as text: %s", b)
	}
}

func TestDetailBudgetEvictsOldest(t *testing.T) {
	q := NewRequests(100)
	one := detailWith(1000).prepared().size
	q.SetMaxDetailBytes(one*3 + one/2) // room for three details
	var ids []uint64
	for range 5 {
		ids = append(ids, q.Add(Request{Path: "/x", Detail: detailWith(1000)}))
	}
	for i, id := range ids {
		r, ok := q.Get(id)
		if !ok {
			t.Fatalf("request %d vanished", id)
		}
		if want := i >= 2; (r.Detail != nil) != want || r.HasDetail != want {
			t.Errorf("request %d: detail %v, has_detail %v, want %v", id, r.Detail != nil, r.HasDetail, want)
		}
	}
	if got := q.DetailBytes(); got != one*3 {
		t.Errorf("DetailBytes %d, want %d", got, one*3)
	}
	// A detail bigger than the whole budget is not kept, and does not evict the others.
	if id := q.Add(Request{Detail: detailWith(MaxBodyBytes)}); func() bool { r, _ := q.Get(id); return r.Detail != nil }() {
		t.Error("oversized detail was kept")
	}
	if got := q.DetailBytes(); got != one*3 {
		t.Errorf("DetailBytes after oversized: %d", got)
	}
	// Queries never carry details.
	for _, r := range q.Query(RequestFilter{}) {
		if r.Detail != nil {
			t.Fatal("Query returned a detail")
		}
	}
	q.SetMaxDetailBytes(0)
	if id := q.Add(Request{Detail: detailWith(10)}); func() bool { r, _ := q.Get(id); return r.Detail != nil }() {
		t.Error("detail kept with a zero budget")
	}
}

func TestDetailAccountingWhenRingWraps(t *testing.T) {
	q := NewRequests(4)
	for range 3 {
		q.Add(Request{Detail: detailWith(10)}) // 1..3
	}
	q.Add(Request{}) // 4: no detail
	for range 10 {
		q.Add(Request{Detail: detailWith(10)})
	}
	n := 0
	for _, r := range q.Query(RequestFilter{}) {
		if r.HasDetail {
			n++
		}
	}
	got, _ := q.Get(q.r.seq)
	if n != 4 || q.DetailBytes() != 4*got.Detail.size {
		t.Errorf("%d entries with detail, %d bytes charged (one is %d)", n, q.DetailBytes(), got.Detail.size)
	}
	if len(q.detailIDs)-q.detailHead != 4 {
		t.Errorf("detail queue holds %d live ids", len(q.detailIDs)-q.detailHead)
	}
}
