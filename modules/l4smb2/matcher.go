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
	"bytes"
	"encoding/binary"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchSMB2{})
}

// MatchSMB2 matches connections that speak SMB2 or SMB3 protocol.
// It identifies the SMB2/3 header by checking the protocol magic bytes,
// the fixed StructureSize of 64, and a valid Command code, as described
// in [MS-SMB2] section 2.2.1.
type MatchSMB2 struct {
	// If true, also match SMB1 (NetBIOS/CIFS) connections by detecting the
	// legacy 0xFF 'S' 'M' 'B' magic. Defaults to false.
	AllowSMB1 bool `json:"allow_smb1,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (m *MatchSMB2) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.smb2",
		New: func() caddy.Module { return new(MatchSMB2) },
	}
}

// Match returns true if the connection looks like SMB2/3.
// It reads the minimum amount of bytes necessary (the NetBIOS session
// service header + the SMB2 header = 4 + 64 bytes) without consuming
// them, so subsequent handlers still see the original stream.
func (m *MatchSMB2) Match(cx *layer4.Connection) (bool, error) {
	// We need at least 4 (NetBIOS) + 4 (ProtocolId) + 2 (StructureSize) +
	// 2 (CreditCharge) + 4 (Status) + 2 (Command) = 18 bytes to perform a
	// meaningful check. Reading the full 68-byte NetBIOS+SMB2 header gives
	// us everything we need and keeps the logic clean.
	buf := make([]byte, SMB2NetBIOSHeaderSize+SMB2HeaderSize)
	n, err := io.ReadFull(cx, buf)
	if err != nil || n < len(buf) {
		// Not enough data: not SMB2.
		return false, nil //nolint:nilerr
	}

	// The SMB2 header starts immediately after the 4-byte NetBIOS
	// Session Service header.
	smb2Header := buf[SMB2NetBIOSHeaderSize:]

	// --- Check 1: Protocol magic bytes ---
	// SMB2/3 always starts with 0xFE 'S' 'M' 'B'.
	// If allow_smb1 is set we also accept 0xFF 'S' 'M' 'B'.
	if bytes.Equal(smb2Header[SMB2OffProtocolID:SMB2OffProtocolID+4], smb1Magic[:]) {
		return m.AllowSMB1, nil
	}
	if !bytes.Equal(smb2Header[SMB2OffProtocolID:SMB2OffProtocolID+4], smb2Magic[:]) {
		return false, nil
	}

	// --- Check 2: StructureSize MUST be 64 ---
	// [MS-SMB2] 2.2.1.1 / 2.2.1.2: "This MUST be set to 64".
	structureSize := binary.LittleEndian.Uint16(smb2Header[SMB2OffStructureSize : SMB2OffStructureSize+2])
	if structureSize != SMB2HeaderSize {
		return false, nil
	}

	// --- Check 3: Command MUST be a known value ---
	// Valid commands are 0x0000 (NEGOTIATE) through 0x0013 (SERVER_TO_CLIENT_NOTIFICATION).
	command := binary.LittleEndian.Uint16(smb2Header[SMB2OffCommand : SMB2OffCommand+2])
	if command > SMB2CommandMax {
		return false, nil
	}

	// --- Check 4: NextCommand alignment (compound requests) ---
	// If non-zero, it MUST be 8-byte aligned and must not overflow the buffer.
	// [MS-SMB2] 2.2.1.1 / 2.2.1.2: NextCommand field semantics.
	nextCmd := binary.LittleEndian.Uint32(smb2Header[SMB2OffNextCommand : SMB2OffNextCommand+4])
	if nextCmd != 0 {
		if nextCmd%8 != 0 {
			return false, nil
		}
		// We can only verify this for data we have already read.
		if int(nextCmd)+SMB2HeaderSize > len(smb2Header) {
			// Offset goes beyond what we read: indeterminate, allow it.
			// A more thorough check would require reading nextCmd bytes ahead.
		}
	}

	return true, nil
}

// UnmarshalCaddyfile sets up the MatchSMB2 from Caddyfile tokens. Syntax:
//
//	smb2
//	smb2 {
//		allow_smb1
//	}
func (m *MatchSMB2) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line arguments are supported.
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "allow_smb1":
			if d.CountRemainingArgs() != 0 {
				return d.ArgErr()
			}
			m.AllowSMB1 = true
		default:
			return d.Errf("unrecognized %s option '%s'", wrapper, optionName)
		}

		// No nested blocks are supported.
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*MatchSMB2)(nil)
	_ layer4.ConnMatcher    = (*MatchSMB2)(nil)
)

// Protocol magic bytes.
// SMB2/3: 0xFE 'S' 'M' 'B'  [MS-SMB2] section 2.2.1
// SMB1:   0xFF 'S' 'M' 'B'
var (
	smb2Magic = [4]byte{0xFE, 'S', 'M', 'B'}
	smb1Magic = [4]byte{0xFF, 'S', 'M', 'B'}
)

// SMB2/3 header offsets and constants as defined in [MS-SMB2] section 2.2.1.
const (
	// SMB2NetBIOSHeaderSize is the size of the NetBIOS Session Service
	// header that wraps every SMB2 packet when transported over TCP port 445.
	// It consists of 1 byte Message Type + 3 bytes Length.
	SMB2NetBIOSHeaderSize = 4

	// SMB2HeaderSize is the fixed size of the SMB2 packet header in bytes.
	// [MS-SMB2] 2.2.1.1 and 2.2.1.2: StructureSize MUST be 64.
	SMB2HeaderSize = 64

	// Offsets within the SMB2 header (i.e. relative to byte 0 of the SMB2
	// magic, AFTER the NetBIOS framing bytes).
	SMB2OffProtocolID    = 0  // 4 bytes: 0xFE 'S' 'M' 'B'
	SMB2OffStructureSize = 4  // 2 bytes, little-endian, MUST be 64
	SMB2OffCreditCharge  = 6  // 2 bytes
	SMB2OffStatus        = 8  // 4 bytes
	SMB2OffCommand       = 12 // 2 bytes
	SMB2OffCreditReq     = 14 // 2 bytes
	SMB2OffFlags         = 16 // 4 bytes
	SMB2OffNextCommand   = 20 // 4 bytes
	SMB2OffMessageID     = 24 // 8 bytes

	// SMB2 flag bits  [MS-SMB2] 2.2.1.1.
	SMB2FlagsServerToRedir    uint32 = 0x00000001
	SMB2FlagsAsyncCommand     uint32 = 0x00000002
	SMB2FlagsRelatedOps       uint32 = 0x00000004
	SMB2FlagsSigned           uint32 = 0x00000008
	SMB2FlagsPriorityMask     uint32 = 0x00000070
	SMB2FlagsDFSOperations    uint32 = 0x10000000
	SMB2FlagsReplayOperation  uint32 = 0x20000000

	// SMB2CommandMax is the highest valid Command code defined in
	// [MS-SMB2] section 2.2.1 (SMB2 SERVER_TO_CLIENT_NOTIFICATION = 0x0013).
	SMB2CommandMax uint16 = 0x0013
)

// SMB2 command codes  [MS-SMB2] 2.2.1.
const (
	SMB2CommandNegotiate            uint16 = 0x0000
	SMB2CommandSessionSetup         uint16 = 0x0001
	SMB2CommandLogoff               uint16 = 0x0002
	SMB2CommandTreeConnect          uint16 = 0x0003
	SMB2CommandTreeDisconnect       uint16 = 0x0004
	SMB2CommandCreate               uint16 = 0x0005
	SMB2CommandClose                uint16 = 0x0006
	SMB2CommandFlush                uint16 = 0x0007
	SMB2CommandRead                 uint16 = 0x0008
	SMB2CommandWrite                uint16 = 0x0009
	SMB2CommandLock                 uint16 = 0x000A
	SMB2CommandIoctl                uint16 = 0x000B
	SMB2CommandCancel               uint16 = 0x000C
	SMB2CommandEcho                 uint16 = 0x000D
	SMB2CommandQueryDirectory       uint16 = 0x000E
	SMB2CommandChangeNotify         uint16 = 0x000F
	SMB2CommandQueryInfo            uint16 = 0x0010
	SMB2CommandSetInfo              uint16 = 0x0011
	SMB2CommandOplockBreak          uint16 = 0x0012
	SMB2CommandServerToClientNotify uint16 = 0x0013
)

// Server Message Block Protocol Versions 2 and 3
// ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5
// ref: https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SMB2/%5BMS-SMB2%5D.pdf
//
// Every SMB2 packet transported over TCP port 445 is prefixed with a 4-byte
// NetBIOS Session Service header (RFC 1002 §4.3.2):
//
//	[0]     Message Type (1 byte)  = 0x00 (SESSION MESSAGE)
//	[1-3]   Length   (3 bytes, big-endian) = length of the following SMB2 data
//
// The SMB2 header immediately follows and MUST be exactly 64 bytes:
//
//	[0-3]   ProtocolId   = 0xFE 0x53 0x4D 0x42  (0xFE 'S' 'M' 'B')
//	[4-5]   StructureSize = 64  (little-endian)
//	[6-7]   CreditCharge
//	[8-11]  (ChannelSequence,Reserved) / Status
//	[12-13] Command       (one of SMB2CommandNegotiate … SMB2CommandServerToClientNotify)
//	[14-15] CreditRequest / CreditResponse
//	[16-19] Flags
//	[20-23] NextCommand   (0 or 8-byte-aligned offset to next compound header)
//	[24-31] MessageId
//	[32-39] AsyncId  (ASYNC header) / Reserved+TreeId  (SYNC header)
//	[40-47] SessionId
//	[48-63] Signature     (16 bytes, all zero when not signed)
