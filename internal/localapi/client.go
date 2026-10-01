// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	dialTimeout           = 5 * time.Second
	responseHeaderTimeout = 60 * time.Second
	clientIdleTimeout     = 30 * time.Second
	maxResponseBytes      = 16 << 20
	maxErrorBytes         = 64 << 10
	maxEventLineBytes     = 1 << 20
)

// ErrStopStream can be returned by a stream callback of [Client.Attach] and [Client.Events] to end the stream
// cleanly; the method then returns nil.
var ErrStopStream = errors.New("localapi: stop stream")

// Client talks to the local API of a daemon over its unix socket.
type Client struct {
	hc   *http.Client
	base string
}

// NewClient returns a client for the daemon socket at socketPath. Nothing is dialled until the first call. Call
// [Client.Close] to release idle connections.
func NewClient(socketPath string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dialTimeout}
			return d.DialContext(ctx, "unix", socketPath)
		},
		ResponseHeaderTimeout: responseHeaderTimeout,
		IdleConnTimeout:       clientIdleTimeout,
		MaxIdleConns:          2,
		DisableCompression:    true,
	}
	// No http.Client.Timeout: it would cut the event streams. Callers bound calls with their context.
	return &Client{hc: &http.Client{Transport: tr}, base: "http://" + Host}
}

// Close closes idle connections. The client stays usable.
func (c *Client) Close() { c.hc.CloseIdleConnections() }

// Status returns the daemon state.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	err := c.call(ctx, http.MethodGet, "/v1/status", nil, &st)
	return st, err
}

// Tunnels lists the tunnels of the daemon.
func (c *Client) Tunnels(ctx context.Context) ([]Tunnel, error) {
	var ts []Tunnel
	err := c.call(ctx, http.MethodGet, "/v1/tunnels", nil, &ts)
	return ts, err
}

// AddTunnel adds a runtime tunnel (it stays until [Client.RemoveTunnel] or a daemon restart); req.Lifetime is
// ignored. It returns once the daemon has accepted the tunnel; the state may still be pending, watch [Client.Events].
func (c *Client) AddTunnel(ctx context.Context, req AddTunnelRequest) (Tunnel, error) {
	req.Lifetime = LifetimeRuntime
	var t Tunnel
	err := c.call(ctx, http.MethodPost, "/v1/tunnels", req, &t)
	return t, err
}

// RemoveTunnel removes a tunnel by name.
func (c *Client) RemoveTunnel(ctx context.Context, name string) error {
	return c.call(ctx, http.MethodDelete, "/v1/tunnels/"+url.PathEscape(name), nil, nil)
}

// Reload asks the daemon to re-read its tunnels file.
func (c *Client) Reload(ctx context.Context) (ReloadResult, error) {
	var res ReloadResult
	err := c.call(ctx, http.MethodPost, "/v1/reload", nil, &res)
	return res, err
}

// Attach adds an attached tunnel and streams its events to fn, which runs in the calling goroutine. The daemon
// removes the tunnel when the stream ends, so Attach blocks for as long as the tunnel should live: until ctx is
// done (it then returns ctx.Err()), the daemon ends the stream (nil), or fn returns an error ([ErrStopStream]
// ends cleanly with nil, anything else is returned as is). req.Lifetime is ignored.
//
// The first event has Type [EventAttached] and carries the accepted Tunnel; after it come the connected and
// disconnected events and the events of this tunnel (tunnel_ready, tunnel_closed). A failed registration arrives as
// tunnel_closed with Error set; the stream stays open, so fn should return an error to end it. When the daemon
// rejects the request, Attach returns the *Error without calling fn.
func (c *Client) Attach(ctx context.Context, req AddTunnelRequest, fn func(Event) error) error {
	req.Lifetime = LifetimeAttached
	return c.stream(ctx, http.MethodPost, "/v1/tunnels", req, fn)
}

// Events streams daemon events to fn until ctx is done (returns ctx.Err()), the daemon ends the stream (nil), or fn
// returns an error (see [Client.Attach]). Events may be missed if fn is slow.
func (c *Client) Events(ctx context.Context, fn func(Event) error) error {
	return c.stream(ctx, http.MethodGet, "/v1/events", nil, fn)
}

func (c *Client) newRequest(ctx context.Context, method, path string, in any) (*http.Request, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("localapi: encoding request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, fmt.Errorf("localapi: building request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// call performs a one-shot request and decodes the JSON answer into out (if not nil).
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	req, err := c.newRequest(ctx, method, path, in)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("localapi: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return decodeError(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("localapi: decoding %s %s response: %w", method, path, err)
	}
	return nil
}

// stream performs a request whose successful answer is an NDJSON stream of events.
func (c *Client) stream(ctx context.Context, method, path string, in any, fn func(Event) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	req, err := c.newRequest(ctx, method, path, in)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/x-ndjson")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("localapi: %s %s: %w", method, path, err)
	}
	// Closing a body that was not read to the end drops the connection, which is what removes an attached tunnel.
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return decodeError(resp)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4096), maxEventLineBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return fmt.Errorf("localapi: decoding event: %w", err)
		}
		if err := fn(ev); err != nil {
			if errors.Is(err, ErrStopStream) {
				return nil
			}
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("localapi: reading event stream: %w", err)
	}
	return nil
}

// decodeError turns a non-success response into an *Error.
func decodeError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
	var body errorBody
	if err := json.Unmarshal(data, &body); err == nil && body.Error != nil && body.Error.Code != "" {
		return body.Error
	}
	return NewError(CodeInternal, "unexpected response %s from the daemon", resp.Status)
}
