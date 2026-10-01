// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eto-a/porthole/internal/adminapi"
	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/proto"
	"github.com/eto-a/porthole/internal/store"
)

// defaultRemoteOpenTimeout is how long RequestTunnel waits for the client's open_result.
const defaultRemoteOpenTimeout = 15 * time.Second

// maxRemoteMessage caps the text of a client's error that is passed on to the operator.
const maxRemoteMessage = 300

// remoteAllowed reports whether the holder of tok accepts remote tunnel requests: the token's RemoteControl flag,
// set when the token is created (`portholed token create`, join links). The client's own allow_remote policy is a
// second, independent limit.
func remoteAllowed(tok *store.Token) bool { return tok != nil && tok.RemoteControl }

// openWaiters matches open_result messages with the RequestTunnel calls that wait for them.
type openWaiters struct {
	mu   sync.Mutex
	next int
	m    map[int]chan *proto.OpenResult
}

// add registers a waiter and returns its request id and the channel that receives the result.
func (w *openWaiters) add() (int, <-chan *proto.OpenResult) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.next++
	ch := make(chan *proto.OpenResult, 1)
	w.m[w.next] = ch
	return w.next, ch
}

func (w *openWaiters) remove(id int) {
	w.mu.Lock()
	delete(w.m, id)
	w.mu.Unlock()
}

// deliver hands a result to its waiter. A result nobody waits for (late, duplicate or invented) is dropped.
func (w *openWaiters) deliver(res *proto.OpenResult) {
	w.mu.Lock()
	ch := w.m[res.ReqID]
	delete(w.m, res.ReqID)
	w.mu.Unlock()
	if ch != nil {
		ch <- res // buffered, one result per id
	}
}

// RequestTunnel implements adminapi.Backend: it asks the named client to open a tunnel and waits for the answer.
func (b adminBackend) RequestTunnel(ctx context.Context, client string, req adminapi.RemoteOpen) (adminapi.RemoteTunnel, error) {
	s := b.s
	switch req.Kind {
	case proto.KindHTTP, proto.KindTCP, proto.KindSSH:
	default:
		return adminapi.RemoteTunnel{}, &adminapi.RemoteError{Code: proto.CodeInvalidRequest, Message: "kind must be http, tcp or ssh"}
	}
	if req.Name != "" && !auth.ValidName(req.Name) {
		return adminapi.RemoteTunnel{}, &adminapi.RemoteError{Code: proto.CodeInvalidRequest, Message: "invalid tunnel name"}
	}
	if req.LocalAddr == "" && req.Kind != proto.KindSSH {
		return adminapi.RemoteTunnel{}, &adminapi.RemoteError{Code: proto.CodeInvalidRequest, Message: "local_addr is required"}
	}

	s.mu.Lock()
	c := s.sessions[client]
	s.mu.Unlock()
	if c == nil {
		return adminapi.RemoteTunnel{}, adminapi.ErrNotFound
	}

	sctx, cancel := context.WithTimeout(ctx, storeTimeout)
	tok, err := s.store.GetToken(sctx, c.tokenID)
	cancel()
	if err != nil {
		return adminapi.RemoteTunnel{}, fmt.Errorf("load token of client %q: %w", client, err)
	}
	if !remoteAllowed(tok) {
		return adminapi.RemoteTunnel{}, &adminapi.RemoteError{
			Code: adminapi.CodeRemoteDisabled, Message: "remote control is not enabled for this client",
		}
	}
	if !c.remoteOpen {
		return adminapi.RemoteTunnel{}, &adminapi.RemoteError{
			Code: proto.CodeClientUnsupported, Message: "this client does not accept remote tunnel requests: run it as the porthole daemon, or update it",
		}
	}

	id, ch := c.opens.add()
	defer c.opens.remove(id)
	err = c.send(&proto.OpenRequest{
		ReqID: id, Kind: req.Kind, LocalAddr: req.LocalAddr, Name: req.Name, Private: req.Private,
		RemotePort: req.RemotePort, RequestedBy: req.RequestedBy,
	})
	if err != nil {
		c.kill("control write failed: "+err.Error(), nil)
		return adminapi.RemoteTunnel{}, &adminapi.RemoteError{Code: proto.CodeInternal, Message: "client connection lost"}
	}
	c.log.Info("remote tunnel requested", "kind", req.Kind, "local", req.LocalAddr, "name", req.Name, "by", req.RequestedBy)

	timer := time.NewTimer(s.openTimeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return remoteResult(res)
	case <-timer.C:
		return adminapi.RemoteTunnel{}, &adminapi.RemoteError{Code: proto.CodeTimeout, Message: "the client did not answer in time"}
	case <-c.ctx.Done():
		return adminapi.RemoteTunnel{}, &adminapi.RemoteError{Code: proto.CodeInternal, Message: "the client disconnected"}
	case <-ctx.Done():
		return adminapi.RemoteTunnel{}, ctx.Err()
	}
}

// remoteResult converts the client's answer. The client is not trusted: unknown codes become "internal" and the
// text is truncated.
func remoteResult(res *proto.OpenResult) (adminapi.RemoteTunnel, error) {
	if res.OK {
		if res.Tunnel == nil {
			return adminapi.RemoteTunnel{}, &adminapi.RemoteError{Code: proto.CodeInternal, Message: "the client reported success without a tunnel"}
		}
		t := res.Tunnel
		return adminapi.RemoteTunnel{Name: t.Name, Kind: t.Kind, URL: t.PublicURL, SSHJump: t.SSHJump}, nil
	}
	e := res.Error
	if e == nil {
		return adminapi.RemoteTunnel{}, errors.New("the client reported failure without an error")
	}
	code := e.Code
	switch code {
	case proto.CodeNotAllowed, proto.CodeNameTaken, proto.CodeInvalidRequest, proto.CodePortUnavailable,
		proto.CodeLimitExceeded, proto.CodeForbidden, proto.CodeTimeout, proto.CodeClientUnsupported:
	default:
		code = proto.CodeInternal
	}
	msg := e.Message
	if len(msg) > maxRemoteMessage {
		msg = msg[:maxRemoteMessage]
	}
	return adminapi.RemoteTunnel{}, &adminapi.RemoteError{Code: code, Message: msg}
}
