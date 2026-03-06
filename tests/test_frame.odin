package ws_tests

import "core:testing"
import "core:mem"
import ws "../websocket"

// --- Build and parse round-trip ---

@(test)
test_build_unmasked_text_frame :: proc(t: ^testing.T) {
	payload := transmute([]u8)string("Hello")
	frame_data, err := ws.build_frame(.Text, payload, false)
	defer delete(frame_data)

	testing.expect(t, err == .None, "build should succeed")
	// FIN=1, opcode=1 => 0x81
	testing.expect_value(t, frame_data[0], u8(0x81))
	// No mask, len=5
	testing.expect_value(t, frame_data[1], u8(5))
	// Payload starts at byte 2
	testing.expect_value(t, string(frame_data[2:7]), "Hello")
}

@(test)
test_build_masked_text_frame :: proc(t: ^testing.T) {
	payload := transmute([]u8)string("Hi")
	frame_data, err := ws.build_frame(.Text, payload, true)
	defer delete(frame_data)

	testing.expect(t, err == .None, "build should succeed")
	testing.expect_value(t, frame_data[0], u8(0x81)) // FIN + Text
	testing.expect_value(t, frame_data[1] & 0x80, u8(0x80)) // MASK bit set
	testing.expect_value(t, frame_data[1] & 0x7F, u8(2)) // payload len = 2
	// 4 bytes mask key at offset 2, then 2 bytes masked payload
	testing.expect_value(t, len(frame_data), 2 + 4 + 2)
}

@(test)
test_parse_unmasked_text_frame :: proc(t: ^testing.T) {
	// Build a text frame with "Hello" unmasked
	raw := [?]u8{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'}

	frame, consumed, err := ws.parse_frame(raw[:])
	defer ws.frame_destroy(&frame)

	testing.expect(t, err == .None, "parse should succeed")
	testing.expect_value(t, consumed, 7)
	testing.expect(t, frame.fin, "should be FIN")
	testing.expect_value(t, frame.opcode, ws.Opcode.Text)
	testing.expect(t, !frame.masked, "should not be masked")
	testing.expect_value(t, string(frame.payload), "Hello")
}

@(test)
test_parse_masked_text_frame :: proc(t: ^testing.T) {
	// Masked "Hi" with mask key [0x37, 0xfa, 0x21, 0x3d]
	// 'H' ^ 0x37 = 0x7f, 'i' ^ 0xfa = 0x93
	raw := [?]u8{0x81, 0x82, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x93}

	frame, consumed, err := ws.parse_frame(raw[:])
	defer ws.frame_destroy(&frame)

	testing.expect(t, err == .None, "parse should succeed")
	testing.expect_value(t, consumed, 8)
	testing.expect(t, frame.masked, "should be masked")
	testing.expect_value(t, string(frame.payload), "Hi")
}

@(test)
test_roundtrip_unmasked :: proc(t: ^testing.T) {
	original := transmute([]u8)string("WebSocket test!")
	frame_data, build_err := ws.build_frame(.Binary, original, false)
	defer delete(frame_data)
	testing.expect(t, build_err == .None, "build")

	frame, _, parse_err := ws.parse_frame(frame_data)
	defer ws.frame_destroy(&frame)
	testing.expect(t, parse_err == .None, "parse")
	testing.expect_value(t, frame.opcode, ws.Opcode.Binary)
	testing.expect(t, frame.fin, "FIN")
	testing.expect_value(t, string(frame.payload), "WebSocket test!")
}

@(test)
test_roundtrip_masked :: proc(t: ^testing.T) {
	original := transmute([]u8)string("masked data")
	frame_data, build_err := ws.build_frame(.Text, original, true)
	defer delete(frame_data)
	testing.expect(t, build_err == .None, "build")

	frame, _, parse_err := ws.parse_frame(frame_data)
	defer ws.frame_destroy(&frame)
	testing.expect(t, parse_err == .None, "parse")
	testing.expect_value(t, string(frame.payload), "masked data")
}

// --- Opcode tests ---

@(test)
test_ping_frame :: proc(t: ^testing.T) {
	frame_data, err := ws.build_frame(.Ping, nil, false)
	defer delete(frame_data)
	testing.expect(t, err == .None, "build ping")
	testing.expect_value(t, frame_data[0], u8(0x89)) // FIN + Ping
}

@(test)
test_pong_frame :: proc(t: ^testing.T) {
	frame_data, err := ws.build_frame(.Pong, nil, false)
	defer delete(frame_data)
	testing.expect(t, err == .None, "build pong")
	testing.expect_value(t, frame_data[0], u8(0x8A)) // FIN + Pong
}

@(test)
test_close_frame :: proc(t: ^testing.T) {
	frame_data, err := ws.build_close_frame(ws.CLOSE_NORMAL, "", false)
	defer delete(frame_data)
	testing.expect(t, err == .None, "build close")
	testing.expect_value(t, frame_data[0], u8(0x88)) // FIN + Close
	// Payload: 2 bytes for status code 1000
	testing.expect_value(t, frame_data[1], u8(2)) // length = 2
	testing.expect_value(t, frame_data[2], u8(0x03)) // 1000 >> 8
	testing.expect_value(t, frame_data[3], u8(0xE8)) // 1000 & 0xFF
}

// --- Extended payload length ---

@(test)
test_medium_payload :: proc(t: ^testing.T) {
	// 200 bytes payload (uses 16-bit extended length)
	payload := make([]u8, 200)
	defer delete(payload)
	for i in 0 ..< 200 {
		payload[i] = u8(i % 256)
	}

	frame_data, build_err := ws.build_frame(.Binary, payload, false)
	defer delete(frame_data)
	testing.expect(t, build_err == .None, "build")

	testing.expect_value(t, frame_data[1] & 0x7F, u8(126)) // extended 16-bit
	testing.expect_value(t, frame_data[2], u8(0))    // 200 >> 8
	testing.expect_value(t, frame_data[3], u8(200))  // 200 & 0xFF

	frame, _, parse_err := ws.parse_frame(frame_data)
	defer ws.frame_destroy(&frame)
	testing.expect(t, parse_err == .None, "parse")
	testing.expect_value(t, len(frame.payload), 200)
	testing.expect_value(t, frame.payload[0], u8(0))
	testing.expect_value(t, frame.payload[199], u8(199))
}

// --- Incomplete data ---

@(test)
test_incomplete_header :: proc(t: ^testing.T) {
	raw := [?]u8{0x81}
	_, _, err := ws.parse_frame(raw[:])
	testing.expect_value(t, err, ws.Frame_Error.Incomplete)
}

@(test)
test_incomplete_payload :: proc(t: ^testing.T) {
	// Header says 5 bytes but only 2 provided
	raw := [?]u8{0x81, 0x05, 'H', 'e'}
	_, _, err := ws.parse_frame(raw[:])
	testing.expect_value(t, err, ws.Frame_Error.Incomplete)
}

// --- Empty payload ---

@(test)
test_empty_payload :: proc(t: ^testing.T) {
	frame_data, build_err := ws.build_frame(.Text, nil, false)
	defer delete(frame_data)
	testing.expect(t, build_err == .None, "build")
	testing.expect_value(t, len(frame_data), 2)

	frame, consumed, parse_err := ws.parse_frame(frame_data)
	defer ws.frame_destroy(&frame)
	testing.expect(t, parse_err == .None, "parse")
	testing.expect_value(t, consumed, 2)
	testing.expect(t, frame.payload == nil, "payload should be nil")
}
