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

// buildDirectPacket returns a 68-byte buffer where the SMB2 header is at
// offset 0 (Direct TCP / port 445, no NetBIOS framing).
func buildDirectPacket() []byte {
	pkt := make([]byte, SMB2NetBIOSHeaderSize+SMB2HeaderSize)
	writeSMB2Header(pkt, 0)
	return pkt
}

// buildNetBIOSPacket returns a 68-byte buffer where the first 4 bytes are a
// NetBIOS Session Service header and the SMB2 header starts at offset 4
// (port 139 transport).
func buildNetBIOSPacket() []byte {
	pkt := make([]byte, SMB2NetBIOSHeaderSize+SMB2HeaderSize)
	// NetBIOS SESSION MESSAGE, length = SMB2HeaderSize
	pkt[0] = 0x00
	binary.BigEndian.PutUint32(pkt[0:4], uint32(SMB2HeaderSize)) // upper byte is type=0
	writeSMB2Header(pkt, SMB2NetBIOSHeaderSize)
	return pkt
}

// writeSMB2Header writes a minimal valid SMB2 NEGOTIATE header into buf
// starting at the given offset.
func writeSMB2Header(buf []byte, offset int) {
	hdr := buf[offset:]
	copy(hdr[SMB2OffProtocolID:], smb2Magic[:])
	binary.LittleEndian.PutUint16(hdr[SMB2OffStructureSize:], SMB2HeaderSize)
	binary.LittleEndian.PutUint16(hdr[SMB2OffCommand:], SMB2CommandNegotiate)
	binary.LittleEndian.PutUint32(hdr[SMB2OffNextCommand:], 0)
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

// ---- Direct TCP (port 445) tests ----

func TestMatchSMB2_DirectTCP_Valid(t *testing.T) {
	if !matchSMB2(t, &MatchSMB2{}, buildDirectPacket()) {
		t.Fatal("expected Direct TCP SMB2 NEGOTIATE to match")
	}
}

func TestMatchSMB2_DirectTCP_AllCommands(t *testing.T) {
	m := &MatchSMB2{}
	for cmd := uint16(0); cmd <= SMB2CommandMax; cmd++ {
		pkt := buildDirectPacket()
		binary.LittleEndian.PutUint16(pkt[SMB2OffCommand:], cmd)
		if !matchSMB2(t, m, pkt) {
			t.Errorf("Direct TCP: expected command 0x%04X to match", cmd)
		}
	}
}

func TestMatchSMB2_DirectTCP_InvalidCommand(t *testing.T) {
	pkt := buildDirectPacket()
	binary.LittleEndian.PutUint16(pkt[SMB2OffCommand:], SMB2CommandMax+1)
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("Direct TCP: expected invalid command to NOT match")
	}
}

func TestMatchSMB2_DirectTCP_BadStructureSize(t *testing.T) {
	pkt := buildDirectPacket()
	binary.LittleEndian.PutUint16(pkt[SMB2OffStructureSize:], 32)
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("Direct TCP: expected wrong StructureSize to NOT match")
	}
}

// ---- NetBIOS (port 139) tests ----

func TestMatchSMB2_NetBIOS_Valid(t *testing.T) {
	if !matchSMB2(t, &MatchSMB2{}, buildNetBIOSPacket()) {
		t.Fatal("expected NetBIOS-framed SMB2 NEGOTIATE to match")
	}
}

func TestMatchSMB2_NetBIOS_AllCommands(t *testing.T) {
	m := &MatchSMB2{}
	for cmd := uint16(0); cmd <= SMB2CommandMax; cmd++ {
		pkt := buildNetBIOSPacket()
		binary.LittleEndian.PutUint16(pkt[SMB2NetBIOSHeaderSize+SMB2OffCommand:], cmd)
		if !matchSMB2(t, m, pkt) {
			t.Errorf("NetBIOS: expected command 0x%04X to match", cmd)
		}
	}
}

func TestMatchSMB2_NetBIOS_InvalidCommand(t *testing.T) {
	pkt := buildNetBIOSPacket()
	binary.LittleEndian.PutUint16(pkt[SMB2NetBIOSHeaderSize+SMB2OffCommand:], SMB2CommandMax+1)
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("NetBIOS: expected invalid command to NOT match")
	}
}

// ---- SMB1 tests ----

func TestMatchSMB2_SMB1_RejectedByDefault(t *testing.T) {
	pkt := buildDirectPacket()
	copy(pkt[SMB2OffProtocolID:], smb1Magic[:])
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected SMB1 magic to NOT match when AllowSMB1=false")
	}
}

func TestMatchSMB2_SMB1_AllowedWhenFlagSet(t *testing.T) {
	pkt := buildDirectPacket()
	copy(pkt[SMB2OffProtocolID:], smb1Magic[:])
	if !matchSMB2(t, &MatchSMB2{AllowSMB1: true}, pkt) {
		t.Fatal("expected SMB1 magic to match when AllowSMB1=true")
	}
}

// ---- Generic tests ----

func TestMatchSMB2_TooShort(t *testing.T) {
	pkt := buildDirectPacket()[:10]
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected truncated packet to NOT match")
	}
}

func TestMatchSMB2_BadMagic(t *testing.T) {
	pkt := buildDirectPacket()
	pkt[SMB2OffProtocolID] = 0x00
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected corrupted magic to NOT match")
	}
}

func TestMatchSMB2_NextCommandMisaligned(t *testing.T) {
	pkt := buildDirectPacket()
	binary.LittleEndian.PutUint32(pkt[SMB2OffNextCommand:], 7) // not 8-aligned
	if matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected misaligned NextCommand to NOT match")
	}
}

func TestMatchSMB2_NextCommandAligned(t *testing.T) {
	pkt := buildDirectPacket()
	binary.LittleEndian.PutUint32(pkt[SMB2OffNextCommand:], 8)
	if !matchSMB2(t, &MatchSMB2{}, pkt) {
		t.Fatal("expected 8-aligned NextCommand to match")
	}
}

// ---- Test helpers ----

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

type pipeConn struct {
	*fixedReader
	net.Conn
}

func (c *pipeConn) Read(b []byte) (int, error) { return c.fixedReader.Read(b) }
func (c *pipeConn) Close() error               { return nil }
func (c *pipeConn) LocalAddr() net.Addr        { return &net.TCPAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr       { return &net.TCPAddr{} }
