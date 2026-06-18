// Copyright 2024 Marco Brunelli
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4smb2

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

// buildPacket returns a complete NetBIOS-framed SMB2 header as a byte slice.
// Callers can mutate individual bytes before passing to matchSMB2.
func buildPacket() []byte {
	pkt := make([]byte, SMB2NetBIOSHeaderSize+SMB2HeaderSize)

	// NetBIOS Session Message (type 0x00)
	pkt[0] = 0x00
	binary.BigEndian.PutUint32(pkt[0:4], uint32(SMB2HeaderSize)) // length in upper 3 bytes

	// SMB2 magic
	copy(pkt[SMB2NetBIOSHeaderSize+SMB2OffProtocolID:], smb2Magic[:])

	// StructureSize = 64 (little-endian)
	binary.LittleEndian.PutUint16(pkt[SMB2NetBIOSHeaderSize+SMB2OffStructureSize:], SMB2HeaderSize)

	// Command = NEGOTIATE (0x0000)
	binary.LittleEndian.PutUint16(pkt[SMB2NetBIOSHeaderSize+SMB2OffCommand:], SMB2CommandNegotiate)

	// NextCommand = 0 (not compounded)
	binary.LittleEndian.PutUint32(pkt[SMB2NetBIOSHeaderSize+SMB2OffNextCommand:], 0)

	return pkt
}

func matchSMB2(t *testing.T, m *MatchSMB2, data []byte) bool {
	t.Helper()

	cx, err := layer4.WrapConnection(
		&pipeConn{Reader: &fixedReader{data: data}},
		[]byte{},
		zap.NewNop(),
	)
	if err != nil {
		t.Fatalf("WrapConnection error: %v", err)
	}
	defer cx.Close()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	cx.SetVar("caddy_context", ctx)

	matched, err := m.Match(cx)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	return matched
}

// --- Tests ---

func TestMatchSMB2_ValidNegotiate(t *testing.T) {
	if !matchSMB2(t, &MatchSMB2{}, buildPacket()) {
		t.Fatal("expected SMB2 NEGOTIATE to match")
	}
}

func TestMatchSMB2_AllCommands(t *testing.T) {
	m := &MatchSMB2{}
	for cmd := uint16(0); cmd <= SMB2CommandMax; cmd++ {
		pkt := buildPacket()
		binary.LittleEndian.PutUint16(pkt[SMB2NetBIOSHeaderSize+SMB2OffCommand:], cmd)
		if !matchSMB2(t, m, pkt) {
			t.Errorf("expected command 0x%04X to match", cmd)
		}
	}
}

func TestMatchSMB2_InvalidCommand(t *testing.T) {
	pkt := buildPacket()
	binary.LittleEndian.PutUint16(pkt[SMB2NetBIOSHeaderSize+SMB2OffCommand:], SMB2CommandMax+1)
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected invalid command to NOT match")
	}
}

func TestMatchSMB2_BadMagic(t *testing.T) {
	pkt := buildPacket()
	pkt[SMB2NetBIOSHeaderSize+SMB2OffProtocolID] = 0x00 // corrupt magic
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected corrupted magic to NOT match")
	}
}

func TestMatchSMB2_BadStructureSize(t *testing.T) {
	pkt := buildPacket()
	binary.LittleEndian.PutUint16(pkt[SMB2NetBIOSHeaderSize+SMB2OffStructureSize:], 32)
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected wrong StructureSize to NOT match")
	}
}

func TestMatchSMB2_TooShort(t *testing.T) {
	pkt := buildPacket()[:10] // truncated
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected truncated packet to NOT match")
	}
}

func TestMatchSMB2_SMB1Rejected(t *testing.T) {
	pkt := buildPacket()
	copy(pkt[SMB2NetBIOSHeaderSize+SMB2OffProtocolID:], smb1Magic[:])
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected SMB1 magic to NOT match when AllowSMB1=false")
	}
}

func TestMatchSMB2_SMB1Allowed(t *testing.T) {
	pkt := buildPacket()
	copy(pkt[SMB2NetBIOSHeaderSize+SMB2OffProtocolID:], smb1Magic[:])
	if !matchSMB2(t, &MatchSMB2{AllowSMB1: true}, pkt) {
		t.Fatal("expected SMB1 magic to match when AllowSMB1=true")
	}
}

func TestMatchSMB2_NextCommandMisaligned(t *testing.T) {
	pkt := buildPacket()
	binary.LittleEndian.PutUint32(pkt[SMB2NetBIOSHeaderSize+SMB2OffNextCommand:], 7) // not 8-aligned
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected misaligned NextCommand to NOT match")
	}
}

func TestMatchSMB2_NextCommandAligned(t *testing.T) {
	pkt := buildPacket()
	// 8 is valid even if it points outside our 68-byte buffer (indeterminate -> allowed)
	binary.LittleEndian.PutUint32(pkt[SMB2NetBIOSHeaderSize+SMB2OffNextCommand:], 8)
	if !matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected aligned NextCommand to match")
	}
}

// --- Test helpers ---

// fixedReader provides a fixed byte slice as an io.Reader.
type fixedReader struct {
	data   []byte
	offset int
}

func (r *fixedReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, net.ErrClosed
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

// pipeConn wraps a Reader to satisfy net.Conn for layer4.WrapConnection.
type pipeConn struct {
	*fixedReader
	net.Conn
}

func (c *pipeConn) Read(b []byte) (int, error) { return c.fixedReader.Read(b) }
func (c *pipeConn) Close() error               { return nil }
func (c *pipeConn) LocalAddr() net.Addr        { return &net.TCPAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr       { return &net.TCPAddr{} }
