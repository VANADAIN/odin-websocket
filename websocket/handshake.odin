package websocket

import "core:crypto"
import "core:crypto/legacy/sha1"
import "core:encoding/base64"
import "core:strings"
import "core:fmt"
import "core:mem"

// WebSocket handshake (RFC 6455 Section 4)
// Client sends HTTP upgrade request, server responds with 101 Switching Protocols.

WS_GUID :: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

Handshake_Error :: enum {
	None,
	Invalid_Response,
	Bad_Status,
	Missing_Accept,
	Invalid_Accept,
	Alloc_Failed,
}

// Build the HTTP upgrade request for a WebSocket connection.
build_handshake_request :: proc(
	host: string,
	path: string,
	key: string,
	allocator := context.allocator,
) -> ([]u8, Handshake_Error) {
	b := strings.builder_make(context.temp_allocator)
	fmt.sbprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.sbprintf(&b, "Host: %s\r\n", host)
	strings.write_string(&b, "Upgrade: websocket\r\n")
	strings.write_string(&b, "Connection: Upgrade\r\n")
	fmt.sbprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	strings.write_string(&b, "Sec-WebSocket-Version: 13\r\n")
	strings.write_string(&b, "\r\n")

	s := strings.to_string(b)
	result := make([]u8, len(s), allocator)
	if result == nil do return nil, .Alloc_Failed
	mem.copy(raw_data(result), raw_data(s), len(s))
	return result, .None
}

// Generate a random 16-byte Sec-WebSocket-Key (base64 encoded).
generate_key :: proc(allocator := context.allocator) -> string {
	random_bytes: [16]u8
	crypto.rand_bytes(random_bytes[:])
	encoded, _ := base64.encode(random_bytes[:], allocator = allocator)
	return encoded
}

// Compute the expected Sec-WebSocket-Accept value for a given key.
compute_accept :: proc(key: string, allocator := context.allocator) -> string {
	// SHA1(key + GUID)
	concat := strings.concatenate({key, WS_GUID}, context.temp_allocator)
	concat_bytes := transmute([]u8)concat

	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, concat_bytes)
	digest: [20]u8
	sha1.final(&ctx, digest[:])

	encoded, _ := base64.encode(digest[:], allocator = allocator)
	return encoded
}

// Validate the server's handshake response.
// Returns .None if the response is valid, error otherwise.
validate_handshake_response :: proc(response: []u8, key: string) -> Handshake_Error {
	resp_str := string(response)

	// Check for HTTP 101
	if !strings.has_prefix(resp_str, "HTTP/1.1 101") {
		return .Bad_Status
	}

	// Find Sec-WebSocket-Accept header
	accept_header := "Sec-WebSocket-Accept: "
	accept_idx := strings.index(resp_str, accept_header)
	if accept_idx < 0 do return .Missing_Accept

	value_start := accept_idx + len(accept_header)
	rest := resp_str[value_start:]
	line_end := strings.index(rest, "\r\n")
	if line_end < 0 do return .Invalid_Accept

	server_accept := rest[:line_end]
	expected_accept := compute_accept(key, context.temp_allocator)

	if server_accept != expected_accept {
		return .Invalid_Accept
	}

	return .None
}

// Find the end of the HTTP response headers (double CRLF).
find_header_end :: proc(data: []u8) -> int {
	s := string(data)
	idx := strings.index(s, "\r\n\r\n")
	if idx < 0 do return -1
	return idx + 4
}
