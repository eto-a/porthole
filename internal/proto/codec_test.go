// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	msgs := []Message{
		&Hello{ProtocolVersion: Version, Token: "ph_abc_def", ClientVersion: "0.1.0", OS: "linux/amd64"},
		&HelloOK{SessionID: "s1", ClientName: "home", HeartbeatIntervalMS: 15000},
		&Register{ReqID: 7, Kind: KindTCP, Name: "ssh", RemotePort: 20022},
		&Register{ReqID: 8, Kind: KindSSH, Name: "nas", Private: true},
		&Registered{ReqID: 8, TunnelID: "t2", Kind: KindSSH, Name: "nas", Private: true, SSHJump: "tun.example.com:2222"},
		&Registered{ReqID: 7, TunnelID: "t1", Kind: KindHTTP, Name: "web", PublicURL: "https://web-home.example.com"},
		&Unregister{TunnelID: "t1"},
		&TunnelClosed{TunnelID: "t1", Reason: "token revoked"},
		&Ping{Seq: 42},
		&Pong{Seq: 42},
		&Error{ReqID: 3, Code: CodeNameTaken, Message: "taken", RetryAfterMS: 500, Fatal: true},
		&StreamHeader{TunnelID: "t1", RemoteAddr: "203.0.113.5:4242"},
		&Unregister{}, // empty object must still carry the type
	}
	var buf bytes.Buffer
	for _, m := range msgs {
		if err := WriteMessage(&buf, m); err != nil {
			t.Fatalf("write %T: %v", m, err)
		}
	}
	for _, want := range msgs {
		got, err := ReadMessage(&buf)
		if err != nil {
			t.Fatalf("read %T: %v", want, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("round trip: got %#v, want %#v", got, want)
		}
	}
	if _, err := ReadMessage(&buf); !errors.Is(err, io.EOF) {
		t.Errorf("after last frame: got %v, want io.EOF", err)
	}
}

func TestWireFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMessage(&buf, &Ping{Seq: 1}); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	n := binary.BigEndian.Uint32(b[:4])
	if got, want := string(b[4:]), `{"type":"ping","seq":1}`; got != want {
		t.Errorf("payload = %s, want %s", got, want)
	}
	if int(n) != len(b)-4 {
		t.Errorf("length prefix %d, payload %d", n, len(b)-4)
	}
}

func frame(payload string) []byte {
	b := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(b, uint32(len(payload)))
	copy(b[4:], payload)
	return b
}

func TestReadErrors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error // nil means "any error"
	}{
		{"zero length", []byte{0, 0, 0, 0}, ErrFrameSize},
		{"too large", []byte{0, 1, 0, 1}, ErrFrameSize},
		{"truncated payload", frame(`{"type":"ping"}`)[:8], io.ErrUnexpectedEOF},
		{"truncated header", []byte{0, 0}, io.ErrUnexpectedEOF},
		{"not json", frame(`hello`), nil},
		{"no type", frame(`{"seq":1}`), nil},
		{"unknown type", frame(`{"type":"teleport"}`), ErrUnknownType},
		{"wrong field type", frame(`{"type":"ping","seq":"x"}`), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadMessage(bytes.NewReader(tt.in))
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestUnknownTypeConsumesFrame(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(frame(`{"type":"future","x":1}`))
	if err := WriteMessage(&buf, &Pong{Seq: 9}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMessage(&buf); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("got %v, want ErrUnknownType", err)
	}
	m, err := ReadMessage(&buf)
	if err != nil || m.(*Pong).Seq != 9 {
		t.Fatalf("next frame: %v %v", m, err)
	}
}

func TestWriteTooLarge(t *testing.T) {
	err := WriteMessage(io.Discard, &Error{Code: CodeInternal, Message: strings.Repeat("x", MaxFrameSize)})
	if !errors.Is(err, ErrFrameSize) {
		t.Fatalf("got %v, want ErrFrameSize", err)
	}
}

func TestReadAs(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteMessage(&buf, &Error{Code: CodeUnauthorized, Message: "bad token"})
	_ = WriteMessage(&buf, &Pong{})
	_ = WriteMessage(&buf, &HelloOK{ClientName: "home"})

	_, err := ReadAs[*HelloOK](&buf)
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != CodeUnauthorized || pe.Retryable() {
		t.Fatalf("error frame: got %v", err)
	}
	if _, err := ReadAs[*HelloOK](&buf); err == nil {
		t.Fatal("pong accepted as hello_ok")
	}
	ok, err := ReadAs[*HelloOK](&buf)
	if err != nil || ok.ClientName != "home" {
		t.Fatalf("hello_ok: %v %v", ok, err)
	}
}

func FuzzReadMessage(f *testing.F) {
	for _, m := range []Message{&Hello{Token: "ph_a_b"}, &Register{Kind: KindHTTP}, &Error{Code: "x"}} {
		var buf bytes.Buffer
		_ = WriteMessage(&buf, m)
		f.Add(buf.Bytes())
	}
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		m, err := ReadMessage(bytes.NewReader(in))
		if err != nil {
			return
		}
		// Anything we decode must re-encode within limits.
		if err := WriteMessage(io.Discard, m); err != nil && !errors.Is(err, ErrFrameSize) {
			t.Fatalf("re-encode %T: %v", m, err)
		}
	})
}
