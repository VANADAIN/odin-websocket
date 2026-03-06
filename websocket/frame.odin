package websocket

import "core:mem"
import "core:crypto"

// WebSocket frame format (RFC 6455 Section 5.2)
//
//  0               1               2               3
//  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |           (16/64)             |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |     Extended payload length continued, if payload len == 127  |
// +-------------------------------+-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------+-------------------------------+

Opcode :: enum u8 {
	Continuation = 0x0,
	Text         = 0x1,
	Binary       = 0x2,
	Close        = 0x8,
	Ping         = 0x9,
	Pong         = 0xA,
}

Frame :: struct {
	fin:     bool,
	opcode:  Opcode,
	masked:  bool,
	mask:    [4]u8,
	payload: []u8,
}

Frame_Error :: enum {
	None,
	Incomplete,
	Invalid_Opcode,
	Payload_Too_Large,
	Alloc_Failed,
}

// Parse a frame from raw bytes. Returns the frame and number of bytes consumed.
parse_frame :: proc(data: []u8, allocator := context.allocator) -> (Frame, int, Frame_Error) {
	if len(data) < 2 do return {}, 0, .Incomplete

	f: Frame
	f.fin = (data[0] & 0x80) != 0
	opcode_val := data[0] & 0x0F
	switch opcode_val {
	case 0x0: f.opcode = .Continuation
	case 0x1: f.opcode = .Text
	case 0x2: f.opcode = .Binary
	case 0x8: f.opcode = .Close
	case 0x9: f.opcode = .Ping
	case 0xA: f.opcode = .Pong
	case: return {}, 0, .Invalid_Opcode
	}

	f.masked = (data[1] & 0x80) != 0
	payload_len := u64(data[1] & 0x7F)
	offset := 2

	if payload_len == 126 {
		if len(data) < offset + 2 do return {}, 0, .Incomplete
		payload_len = u64(data[offset]) << 8 | u64(data[offset + 1])
		offset += 2
	} else if payload_len == 127 {
		if len(data) < offset + 8 do return {}, 0, .Incomplete
		payload_len = 0
		for i in 0 ..< 8 {
			payload_len = payload_len << 8 | u64(data[offset + i])
		}
		offset += 8
	}

	if f.masked {
		if len(data) < offset + 4 do return {}, 0, .Incomplete
		f.mask[0] = data[offset]
		f.mask[1] = data[offset + 1]
		f.mask[2] = data[offset + 2]
		f.mask[3] = data[offset + 3]
		offset += 4
	}

	if u64(len(data) - offset) < payload_len do return {}, 0, .Incomplete

	plen := int(payload_len)
	if plen > 0 {
		payload, alloc_err := make([]u8, plen, allocator)
		if alloc_err != nil do return {}, 0, .Alloc_Failed
		mem.copy(raw_data(payload), &data[offset], plen)

		if f.masked {
			_apply_mask(payload, f.mask)
		}
		f.payload = payload
	}

	return f, offset + plen, .None
}

// Build a frame into bytes. Client frames MUST be masked.
build_frame :: proc(opcode: Opcode, payload: []u8, masked: bool, allocator := context.allocator) -> ([]u8, Frame_Error) {
	plen := len(payload)

	// Calculate frame size
	header_size := 2
	if plen >= 126 && plen <= 65535 {
		header_size += 2
	} else if plen > 65535 {
		header_size += 8
	}

	mask: [4]u8
	if masked {
		header_size += 4
		crypto.rand_bytes(mask[:])
	}

	total := header_size + plen
	buf, alloc_err := make([]u8, total, allocator)
	if alloc_err != nil do return nil, .Alloc_Failed

	// First byte: FIN + opcode
	buf[0] = 0x80 | u8(opcode) // FIN = 1
	offset := 2

	// Second byte: MASK + payload length
	mask_bit := u8(0x80) if masked else u8(0x00)
	if plen < 126 {
		buf[1] = mask_bit | u8(plen)
	} else if plen <= 65535 {
		buf[1] = mask_bit | 126
		buf[offset] = u8(plen >> 8)
		buf[offset + 1] = u8(plen & 0xFF)
		offset += 2
	} else {
		buf[1] = mask_bit | 127
		p := u64(plen)
		for i in 0 ..< 8 {
			buf[offset + i] = u8(p >> uint(56 - i * 8))
		}
		offset += 8
	}

	if masked {
		buf[offset] = mask[0]
		buf[offset + 1] = mask[1]
		buf[offset + 2] = mask[2]
		buf[offset + 3] = mask[3]
		offset += 4
	}

	if plen > 0 {
		mem.copy(&buf[offset], raw_data(payload), plen)
		if masked {
			_apply_mask(buf[offset:offset + plen], mask)
		}
	}

	return buf, .None
}

// Build a close frame with status code.
build_close_frame :: proc(status_code: u16, reason: string = "", masked: bool = true, allocator := context.allocator) -> ([]u8, Frame_Error) {
	reason_bytes := transmute([]u8)reason
	payload_size := 2 + len(reason_bytes)
	payload := make([]u8, payload_size, context.temp_allocator)
	payload[0] = u8(status_code >> 8)
	payload[1] = u8(status_code & 0xFF)
	if len(reason_bytes) > 0 {
		mem.copy(&payload[2], raw_data(reason_bytes), len(reason_bytes))
	}
	return build_frame(.Close, payload, masked, allocator)
}

frame_destroy :: proc(f: ^Frame, allocator := context.allocator) {
	delete(f.payload, allocator)
	f.payload = nil
}

_apply_mask :: proc(data: []u8, mask: [4]u8) {
	for i in 0 ..< len(data) {
		data[i] ~= mask[i % 4]
	}
}
