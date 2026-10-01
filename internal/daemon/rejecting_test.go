// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/transport"
)

// newRejectingServer is a server that answers every hello with the given error code and closes the session.
func newRejectingServer(t *testing.T, code string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(proto.ConnectPath, func(w http.ResponseWriter, r *http.Request) {
		sess, err := transport.AcceptWebSocket(w, r, &net.TCPAddr{})
		if err != nil {
			return
		}
		defer func() { _ = sess.Close() }()
		ctl, err := sess.Accept()
		if err != nil {
			return
		}
		_ = ctl.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := proto.ReadAs[*proto.Hello](ctl); err != nil {
			return
		}
		_ = proto.WriteMessage(ctl, &proto.Error{Code: code, Message: "rejected by the fake server"})
		time.Sleep(50 * time.Millisecond) // let the client read the frame before the connection goes away
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts.URL
}
