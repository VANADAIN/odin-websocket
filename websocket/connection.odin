package websocket

// WebSocket connection state machine.

State :: enum {
	Connecting,
	Open,
	Closing,
	Closed,
}

// Close status codes (RFC 6455 Section 7.4.1)
CLOSE_NORMAL           :: 1000
CLOSE_GOING_AWAY       :: 1001
CLOSE_PROTOCOL_ERROR   :: 1002
CLOSE_UNSUPPORTED_DATA :: 1003
CLOSE_NO_STATUS        :: 1005
CLOSE_ABNORMAL         :: 1006
CLOSE_INVALID_PAYLOAD  :: 1007
CLOSE_POLICY_VIOLATION :: 1008
CLOSE_MESSAGE_TOO_BIG  :: 1009
CLOSE_MANDATORY_EXT    :: 1010
CLOSE_INTERNAL_ERROR   :: 1011
