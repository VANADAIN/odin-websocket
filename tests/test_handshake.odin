package ws_tests

import "core:testing"
import "core:strings"
import "core:encoding/base64"
import ws "../websocket"

// --- Key generation ---

@(test)
test_generate_key_is_base64 :: proc(t: ^testing.T) {
	key := ws.generate_key(context.temp_allocator)
	testing.expect(t, len(key) > 0, "key should not be empty")

	// Base64 of 16 bytes = 24 chars (with padding)
	testing.expect_value(t, len(key), 24)
}

@(test)
test_generate_key_unique :: proc(t: ^testing.T) {
	k1 := ws.generate_key(context.temp_allocator)
	k2 := ws.generate_key(context.temp_allocator)
	testing.expect(t, k1 != k2, "two generated keys should differ")
}

// --- Accept computation ---

@(test)
test_compute_accept_rfc_vector :: proc(t: ^testing.T) {
	// RFC 6455 Section 4.2.2 example
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	expected := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

	result := ws.compute_accept(key, context.temp_allocator)
	testing.expect_value(t, result, expected)
}

// --- Handshake request ---

@(test)
test_build_handshake_request :: proc(t: ^testing.T) {
	request, err := ws.build_handshake_request("example.com", "/chat", "dGhlIHNhbXBsZSBub25jZQ==", context.temp_allocator)
	testing.expect(t, err == .None, "build should succeed")

	req_str := string(request)
	testing.expect(t, strings.has_prefix(req_str, "GET /chat HTTP/1.1\r\n"), "should start with GET")
	testing.expect(t, strings.contains(req_str, "Host: example.com\r\n"), "should have Host header")
	testing.expect(t, strings.contains(req_str, "Upgrade: websocket\r\n"), "should have Upgrade header")
	testing.expect(t, strings.contains(req_str, "Connection: Upgrade\r\n"), "should have Connection header")
	testing.expect(t, strings.contains(req_str, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"), "should have Key header")
	testing.expect(t, strings.contains(req_str, "Sec-WebSocket-Version: 13\r\n"), "should have Version header")
	testing.expect(t, strings.has_suffix(req_str, "\r\n\r\n"), "should end with double CRLF")
}

// --- Handshake response validation ---

@(test)
test_validate_valid_response :: proc(t: ^testing.T) {
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	accept := ws.compute_accept(key, context.temp_allocator)

	resp := strings.concatenate({
		"HTTP/1.1 101 Switching Protocols\r\n",
		"Upgrade: websocket\r\n",
		"Connection: Upgrade\r\n",
		"Sec-WebSocket-Accept: ", accept, "\r\n",
		"\r\n",
	}, context.temp_allocator)

	err := ws.validate_handshake_response(transmute([]u8)resp, key)
	testing.expect_value(t, err, ws.Handshake_Error.None)
}

@(test)
test_validate_bad_status :: proc(t: ^testing.T) {
	resp := "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
	err := ws.validate_handshake_response(transmute([]u8)resp, "somekey")
	testing.expect_value(t, err, ws.Handshake_Error.Bad_Status)
}

@(test)
test_validate_missing_accept :: proc(t: ^testing.T) {
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
	err := ws.validate_handshake_response(transmute([]u8)resp, "somekey")
	testing.expect_value(t, err, ws.Handshake_Error.Missing_Accept)
}

@(test)
test_validate_wrong_accept :: proc(t: ^testing.T) {
	key := "dGhlIHNhbXBsZSBub25jZQ=="

	resp := strings.concatenate({
		"HTTP/1.1 101 Switching Protocols\r\n",
		"Sec-WebSocket-Accept: wrongvalue==\r\n",
		"\r\n",
	}, context.temp_allocator)

	err := ws.validate_handshake_response(transmute([]u8)resp, key)
	testing.expect_value(t, err, ws.Handshake_Error.Invalid_Accept)
}

// --- Header end detection ---

@(test)
test_find_header_end :: proc(t: ^testing.T) {
	data := "HTTP/1.1 101\r\nFoo: bar\r\n\r\nbody"
	result := ws.find_header_end(transmute([]u8)data)
	// \r\n\r\n starts at index 22, end = 22 + 4 = 26
	testing.expect_value(t, result, 26)
}

@(test)
test_find_header_end_not_found :: proc(t: ^testing.T) {
	data := "HTTP/1.1 101\r\nFoo: bar\r\n"
	result := ws.find_header_end(transmute([]u8)data)
	testing.expect_value(t, result, -1)
}

// --- URL parsing ---

@(test)
test_parse_ws_url :: proc(t: ^testing.T) {
	host, port, path, ok := ws._parse_ws_url("ws://example.com/chat")
	testing.expect(t, ok, "should parse ok")
	testing.expect_value(t, host, "example.com")
	testing.expect_value(t, port, "80")
	testing.expect_value(t, path, "/chat")
}

@(test)
test_parse_ws_url_with_port :: proc(t: ^testing.T) {
	host, port, path, ok := ws._parse_ws_url("ws://localhost:8080/ws")
	testing.expect(t, ok, "should parse ok")
	testing.expect_value(t, host, "localhost")
	testing.expect_value(t, port, "8080")
	testing.expect_value(t, path, "/ws")
}

@(test)
test_parse_wss_url :: proc(t: ^testing.T) {
	host, port, path, ok := ws._parse_ws_url("wss://secure.example.com/")
	testing.expect(t, ok, "should parse ok")
	testing.expect_value(t, host, "secure.example.com")
	testing.expect_value(t, port, "443")
	testing.expect_value(t, path, "/")
}

@(test)
test_parse_ws_url_no_path :: proc(t: ^testing.T) {
	host, port, path, ok := ws._parse_ws_url("ws://example.com")
	testing.expect(t, ok, "should parse ok")
	testing.expect_value(t, host, "example.com")
	testing.expect_value(t, path, "/")
}

@(test)
test_parse_invalid_url :: proc(t: ^testing.T) {
	_, _, _, ok := ws._parse_ws_url("http://example.com")
	testing.expect(t, !ok, "should fail for http://")
}
