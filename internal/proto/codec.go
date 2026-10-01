// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrameSize is the largest allowed frame payload in bytes.
const MaxFrameSize = 64 << 10

// ErrFrameSize is returned when a frame length is zero or exceeds MaxFrameSize.
var ErrFrameSize = errors.New("proto: invalid frame size")

// ErrUnknownType is returned by ReadMessage for a well-formed frame whose type this build does not know.
// Callers on the control stream should log and continue; the frame has been fully consumed.
var ErrUnknownType = errors.New("proto: unknown message type")

// WriteMessage encodes m as a single frame and writes it to w with one Write call.
func WriteMessage(w io.Writer, m Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("proto: marshal %s: %w", m.MsgType(), err)
	}
	if len(body) < 2 || body[0] != '{' {
		return fmt.Errorf("proto: %s did not encode as a JSON object", m.MsgType())
	}
	typ, err := json.Marshal(m.MsgType())
	if err != nil {
		return fmt.Errorf("proto: marshal type: %w", err)
	}

	// Splice `"type":"<t>"` into the object: {"type":"x"} or {"type":"x",...}.
	var payload bytes.Buffer
	payload.Grow(len(body) + len(typ) + 9)
	payload.WriteString(`{"type":`)
	payload.Write(typ)
	if len(body) > 2 {
		payload.WriteByte(',')
	}
	payload.Write(body[1:])

	if payload.Len() > MaxFrameSize {
		return fmt.Errorf("%w: %s is %d bytes", ErrFrameSize, m.MsgType(), payload.Len())
	}

	frame := make([]byte, 4+payload.Len())
	binary.BigEndian.PutUint32(frame, uint32(payload.Len())) //nolint:gosec // bounded by MaxFrameSize above
	copy(frame[4:], payload.Bytes())
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("proto: write %s: %w", m.MsgType(), err)
	}
	return nil
}

// ReadMessage reads exactly one frame from r and decodes it.
// It returns ErrUnknownType (with the frame consumed) for types this build does not implement.
func ReadMessage(r io.Reader) (Message, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err // io.EOF on a clean close between frames
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d", ErrFrameSize, n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("proto: read frame: %w", noEOF(err))
	}
	return decode(payload)
}

func decode(payload []byte) (Message, error) {
	var env struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("proto: decode envelope: %w", err)
	}
	if env.Type == "" {
		return nil, errors.New("proto: frame has no type")
	}
	m := newMessage(env.Type)
	if m == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, env.Type)
	}
	if err := json.Unmarshal(payload, m); err != nil {
		return nil, fmt.Errorf("proto: decode %s: %w", env.Type, err)
	}
	return m, nil
}

// ReadAs reads one frame and requires it to be of type T. An *Error frame is returned as an error.
func ReadAs[T Message](r io.Reader) (T, error) {
	var zero T
	m, err := ReadMessage(r)
	if err != nil {
		return zero, err
	}
	if t, ok := m.(T); ok {
		return t, nil
	}
	if e, ok := m.(*Error); ok {
		return zero, e
	}
	return zero, fmt.Errorf("proto: expected %s, got %s", zero.MsgType(), m.MsgType())
}

func noEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
