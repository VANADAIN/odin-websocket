package websocket

import "core:net"
import "core:mem"
import "core:strings"

Client_Error :: enum {
	None,
	Parse_URL_Failed,
	Connect_Failed,
	Handshake_Failed,
	Send_Failed,
	Recv_Failed,
	Frame_Error,
	Not_Connected,
	Already_Closed,
	Alloc_Failed,
}

// Message received from the WebSocket.
Message :: struct {
	opcode:  Opcode,
	payload: []u8,
}

Client :: struct {
	socket: net.TCP_Socket,
	state:  State,
	host:   string,
	path:   string,
	recv_buf: [dynamic]u8,
}

// Connect to a WebSocket server.
// URL format: ws://host:port/path
connect :: proc(url: string, allocator := context.allocator) -> (^Client, Client_Error) {
	host, port, path, ok := _parse_ws_url(url)
	if !ok do return nil, .Parse_URL_Failed

	socket, net_err := net.dial_tcp_from_hostname_and_port_string(
		strings.concatenate({host, ":", port}, context.temp_allocator),
	)
	if net_err != nil do return nil, .Connect_Failed

	// Generate key and send handshake
	key := generate_key(context.temp_allocator)
	host_header := host
	if port != "80" && port != "443" {
		host_header = strings.concatenate({host, ":", port}, context.temp_allocator)
	}

	request, hs_err := build_handshake_request(host_header, path, key, context.temp_allocator)
	if hs_err != .None {
		net.close(socket)
		return nil, .Handshake_Failed
	}

	if _, send_err := net.send_tcp(socket, request); send_err != .None {
		net.close(socket)
		return nil, .Send_Failed
	}

	// Read handshake response
	resp_buf: [4096]u8
	total_read := 0
	for {
		n, recv_err := net.recv_tcp(socket, resp_buf[total_read:])
		if recv_err != .None || n <= 0 {
			net.close(socket)
			return nil, .Recv_Failed
		}
		total_read += n
		header_end := find_header_end(resp_buf[:total_read])
		if header_end > 0 {
			validate_err := validate_handshake_response(resp_buf[:header_end], key)
			if validate_err != .None {
				net.close(socket)
				return nil, .Handshake_Failed
			}
			break
		}
		if total_read >= len(resp_buf) {
			net.close(socket)
			return nil, .Handshake_Failed
		}
	}

	client, alloc_err := new(Client, allocator)
	if alloc_err != nil {
		net.close(socket)
		return nil, .Alloc_Failed
	}

	client.socket = socket
	client.state = .Open
	client.host = strings.clone(host, allocator)
	client.path = strings.clone(path, allocator)

	return client, .None
}

// Send a text message.
send_text :: proc(client: ^Client, text: string, allocator := context.allocator) -> Client_Error {
	if client.state != .Open do return .Not_Connected
	data := transmute([]u8)text
	return _send_frame(client, .Text, data, allocator)
}

// Send a binary message.
send_binary :: proc(client: ^Client, data: []u8, allocator := context.allocator) -> Client_Error {
	if client.state != .Open do return .Not_Connected
	return _send_frame(client, .Binary, data, allocator)
}

// Send a ping.
send_ping :: proc(client: ^Client, payload: []u8 = nil, allocator := context.allocator) -> Client_Error {
	if client.state != .Open do return .Not_Connected
	return _send_frame(client, .Ping, payload, allocator)
}

// Receive the next message. Handles ping/pong/close internally.
recv :: proc(client: ^Client, allocator := context.allocator) -> (Message, Client_Error) {
	if client.state != .Open do return {}, .Not_Connected

	buf: [65536]u8
	for {
		n, recv_err := net.recv_tcp(client.socket, buf[:])
		if recv_err != .None || n <= 0 {
			client.state = .Closed
			return {}, .Recv_Failed
		}

		append(&client.recv_buf, ..buf[:n])

		// Try to parse a complete frame
		frame, consumed, frame_err := parse_frame(client.recv_buf[:], allocator)
		if frame_err == .Incomplete do continue
		if frame_err != .None do return {}, .Frame_Error

		// Remove consumed bytes
		remaining := len(client.recv_buf) - consumed
		if remaining > 0 {
			mem.copy(raw_data(client.recv_buf[:]), &client.recv_buf[consumed], remaining)
		}
		resize(&client.recv_buf, remaining)

		switch frame.opcode {
		case .Ping:
			// Auto-respond with pong
			_send_frame(client, .Pong, frame.payload, context.temp_allocator)
			frame_destroy(&frame, allocator)
			continue
		case .Close:
			// Send close response if we haven't already
			if client.state == .Open {
				client.state = .Closing
				close_frame, _ := build_close_frame(CLOSE_NORMAL, "", true, context.temp_allocator)
				net.send_tcp(client.socket, close_frame)
			}
			client.state = .Closed
			frame_destroy(&frame, allocator)
			return {}, .Already_Closed
		case .Pong:
			frame_destroy(&frame, allocator)
			continue
		case .Text, .Binary, .Continuation:
			return Message{opcode = frame.opcode, payload = frame.payload}, .None
		}
	}
}

// Close the connection gracefully.
close_connection :: proc(client: ^Client, allocator := context.allocator) {
	if client == nil do return

	if client.state == .Open {
		client.state = .Closing
		close_frame, err := build_close_frame(CLOSE_NORMAL, "", true, context.temp_allocator)
		if err == .None {
			net.send_tcp(client.socket, close_frame)
		}
	}

	net.close(client.socket)
	client.state = .Closed
	delete(client.recv_buf)
	delete(client.host, allocator)
	delete(client.path, allocator)
	free(client, allocator)
}

message_destroy :: proc(msg: ^Message, allocator := context.allocator) {
	delete(msg.payload, allocator)
	msg.payload = nil
}

// --- Internal ---

_send_frame :: proc(client: ^Client, opcode: Opcode, payload: []u8, allocator := context.allocator) -> Client_Error {
	frame_data, err := build_frame(opcode, payload, true, context.temp_allocator) // client always masks
	if err != .None do return .Frame_Error

	if _, send_err := net.send_tcp(client.socket, frame_data); send_err != .None {
		return .Send_Failed
	}
	return .None
}

_parse_ws_url :: proc(url: string) -> (host: string, port: string, path: string, ok: bool) {
	s := url
	if strings.has_prefix(s, "ws://") {
		s = s[5:]
		port = "80"
	} else if strings.has_prefix(s, "wss://") {
		s = s[6:]
		port = "443"
	} else {
		return "", "", "", false
	}

	// Split host and path
	path_idx := strings.index_byte(s, '/')
	host_part: string
	if path_idx >= 0 {
		host_part = s[:path_idx]
		path = s[path_idx:]
	} else {
		host_part = s
		path = "/"
	}

	// Check for port in host
	colon_idx := strings.index_byte(host_part, ':')
	if colon_idx >= 0 {
		host = host_part[:colon_idx]
		port = host_part[colon_idx + 1:]
	} else {
		host = host_part
	}

	return host, port, path, true
}
