// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/transport"
)

// fakeServer is a minimal protocol-speaking server: it accepts sessions, answers hello and registers tunnels. It
// does not use internal/server (which cannot be imported from test code of another package).
type fakeServer struct {
	t  *testing.T
	ts *httptest.Server

	mu       sync.Mutex
	conns    int
	regs     []string          // names of every register message, in order
	live     map[string]string // tunnel name -> id of tunnels registered and not unregistered
	unregs   []string          // tunnel ids
	refuse   map[string]string // tunnel name -> error code to answer with
	sessions []transport.Session
	hello    *proto.Hello           // of the last session
	sendLast func(m proto.Message)  // writes to the control stream of the last session
	openRes  chan *proto.OpenResult // every open_result received
	wg       sync.WaitGroup
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{t: t, live: map[string]string{}, refuse: map[string]string{}, openRes: make(chan *proto.OpenResult, 8)}
	mux := http.NewServeMux()
	mux.HandleFunc(proto.ConnectPath, func(w http.ResponseWriter, r *http.Request) {
		sess, err := transport.AcceptWebSocket(w, r, &net.TCPAddr{})
		if err != nil {
			t.Errorf("fake server accept: %v", err)
			return
		}
		fs.mu.Lock()
		fs.conns++
		n := fs.conns
		fs.sessions = append(fs.sessions, sess)
		fs.mu.Unlock()
		fs.wg.Go(func() { fs.serve(sess, n) })
	})
	fs.ts = httptest.NewServer(mux)
	t.Cleanup(func() {
		fs.mu.Lock()
		sessions := slices.Clone(fs.sessions)
		fs.mu.Unlock()
		for _, s := range sessions {
			_ = s.Close()
		}
		fs.wg.Wait()
		fs.ts.Close()
	})
	return fs
}

func (fs *fakeServer) url() string { return fs.ts.URL }

func (fs *fakeServer) serve(sess transport.Session, n int) {
	ctl, err := sess.Accept()
	if err != nil {
		return
	}
	_ = ctl.SetReadDeadline(time.Now().Add(5 * time.Second))
	hello, err := proto.ReadAs[*proto.Hello](ctl)
	if err != nil {
		return
	}
	_ = ctl.SetReadDeadline(time.Time{})
	var wmu sync.Mutex
	send := func(m proto.Message) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = proto.WriteMessage(ctl, m)
	}
	fs.mu.Lock()
	fs.hello, fs.sendLast = hello, send
	fs.mu.Unlock()
	send(&proto.HelloOK{SessionID: "s" + strconv.Itoa(n), ClientName: "home", ServerVersion: "fake", HeartbeatIntervalMS: 15000})
	for {
		m, err := proto.ReadMessage(ctl)
		if err != nil {
			if errors.Is(err, proto.ErrUnknownType) {
				continue
			}
			return
		}
		switch m := m.(type) {
		case *proto.Register:
			fs.mu.Lock()
			fs.regs = append(fs.regs, m.Name)
			code, refused := fs.refuse[m.Name]
			idx := len(fs.regs)
			id := "t" + strconv.Itoa(idx)
			if !refused {
				fs.live[m.Name] = id
			}
			fs.mu.Unlock()
			if refused {
				send(&proto.Error{ReqID: m.ReqID, Code: code, Message: "refused by the fake server"})
				continue
			}
			url := "https://" + m.Name + "-home.tun.test"
			if m.Kind == proto.KindTCP {
				port := m.RemotePort
				if port == 0 {
					port = 20000 + idx
				}
				url = "tcp://tun.test:" + strconv.Itoa(port)
			}
			send(&proto.Registered{ReqID: m.ReqID, TunnelID: id, Kind: m.Kind, Name: m.Name, PublicURL: url})
		case *proto.Unregister:
			fs.mu.Lock()
			fs.unregs = append(fs.unregs, m.TunnelID)
			for name, id := range fs.live {
				if id == m.TunnelID {
					delete(fs.live, name)
				}
			}
			fs.mu.Unlock()
		case *proto.OpenResult:
			fs.openRes <- m
		case *proto.Pong:
		}
	}
}

// liveTunnels returns the names of the registered tunnels, sorted.
func (fs *fakeServer) liveTunnels() []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return slices.Sorted(maps.Keys(fs.live))
}

// registrations returns how many register messages the given tunnel name produced.
func (fs *fakeServer) registrations(name string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := 0
	for _, r := range fs.regs {
		if r == name {
			n++
		}
	}
	return n
}

func (fs *fakeServer) connCount() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.conns
}

func (fs *fakeServer) refuseName(name, code string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.refuse[name] = code
}

// ask sends an open_request on the last session and returns the client's answer.
func (fs *fakeServer) ask(req *proto.OpenRequest) *proto.OpenResult {
	fs.t.Helper()
	fs.mu.Lock()
	send := fs.sendLast
	fs.mu.Unlock()
	send(req)
	select {
	case res := <-fs.openRes:
		return res
	case <-time.After(10 * time.Second):
		fs.t.Fatal("no open_result")
		return nil
	}
}
