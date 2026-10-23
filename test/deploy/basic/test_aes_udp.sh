#!/bin/bash

# Copyright (C) 2026  mieru authors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Make sure this script has executable permission:
# git update-index --chmod=+x <file>

set -e

# Load test library.
source ./libtest.sh

# Test the AES-256-GCM cipher suite over the UDP transport, with the socks5 UDP
# associate data plane of test_mix_udp_associate.sh.
#
# server_aes_udp.json is a mixed listener: it binds the TCP ports 9999-10001 and
# the UDP ports 10002-10003, and it only allows CIPHER_SUITE_AES_256_GCM.
# client_aes_udp.json offers CIPHER_SUITE_AES_256_GCM and the
# CIPHER_SUITE_XCHACHA20_POLY1305 fallback, and it selects the UDP port bindings
# of the server only. Every session of this test therefore runs over the UDP
# transport (a PacketUnderlay), so a successful run proves the AES-256-GCM suite
# end to end over UDP rather than over TCP as test_aes.sh does.
#
# The negotiated suite is only observable in a log line, and that line is
# written at DEBUG level by the client (pkg/protocol/session.go, message
# "<session> handshake completed with protocol ShadowLemon V0.1 and cipher suite <suite>").
# client_aes_udp.json therefore sets "loggingLevel": "DEBUG"; with the "INFO"
# level used by client_udp.json the line is never emitted. The client writes its
# log to $HOME/.cache/mieru/<timestamp>_<pid>.log
# (pkg/log/mieru_client_logging.go, log.NewClientLogFile()).
#
# NOTE: only the client logs the negotiated suite. The server side
# (Session.acceptHandshake) logs nothing when the handshake succeeds; it only
# logs the reasons of a rejection, also at DEBUG level.
CLIENT_LOG_DIR="$HOME/.cache/mieru"
EXPECTED_AES_LINE="handshake completed with protocol ShadowLemon V0.1 and cipher suite AES_256_GCM"
HANDSHAKE_LINE="handshake completed with protocol ShadowLemon V0.1 and cipher suite"
# The client logs "Adding session <id> to <underlay>" at DEBUG level when a
# session is attached to an underlay (pkg/protocol/underlay_packet.go and
# pkg/protocol/underlay_stream.go). The underlay name tells the transport apart:
# PacketUnderlay is the UDP transport and StreamUnderlay is the TCP transport.
PACKET_UNDERLAY_LINE="to PacketUnderlay{"
STREAM_UNDERLAY_LINE="to StreamUnderlay{"

# count_client_log_matches <substring>
# Prints how many lines of the client log contain the given substring.
function count_client_log_matches() {
    local pattern=$1
    local count

    # "grep | wc -l" keeps this non-fatal when the log file is missing or no
    # line matches, so that "set -e" doesn't abort with an empty diagnostic.
    count=$(grep -h -F "$pattern" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | wc -l)
    echo "$((count))"
}

# print_client_log_tail <number of lines>
function print_client_log_tail() {
    local lines=$1

    echo "========== BEGIN TAIL OF CLIENT LOG =========="
    tail -n "$lines" "$CLIENT_LOG_DIR"/*.log 2>/dev/null || true
    echo "==========  END TAIL OF CLIENT LOG  =========="
}

# assert_aes_cipher_suite_over_udp
# Fails the test unless at least one established session logged that it used
# AES-256-GCM, and unless at least one session was attached to a UDP transport
# underlay. An "apparently working" data plane is NOT enough: a silent fallback
# to CIPHER_SUITE_XCHACHA20_POLY1305 would still carry traffic, and a session
# that ran over the TCP transport would still transfer the same payloads.
function assert_aes_cipher_suite_over_udp() {
    local aes_count
    local handshake_count
    local packet_count
    local stream_count

    aes_count=$(count_client_log_matches "$EXPECTED_AES_LINE")
    handshake_count=$(count_client_log_matches "$HANDSHAKE_LINE")
    packet_count=$(count_client_log_matches "$PACKET_UNDERLAY_LINE")
    stream_count=$(count_client_log_matches "$STREAM_UNDERLAY_LINE")

    echo "cipher suite assertion: $handshake_count session(s) completed the ShadowLemon V0.1 handshake,"
    echo "cipher suite assertion: $aes_count of them used AES_256_GCM."
    echo "transport assertion: $packet_count session(s) were attached to the UDP transport and"
    echo "transport assertion: $stream_count session(s) to the TCP transport."

    if [[ "$handshake_count" -eq 0 ]]; then
        echo "cipher suite assertion FAILED: no client log line reports a completed ShadowLemon V0.1 handshake at all,"
        echo "so the session either wasn't established or the client didn't log at DEBUG level."
        echo "the expected log line is written by pkg/protocol/session.go:"
        echo "  handshake completed with protocol ShadowLemon V0.1 and cipher suite <suite>"
        print_client_log_tail 80
        print_client_log
        exit 1
    fi

    if [[ "$aes_count" -eq 0 ]]; then
        echo "cipher suite assertion FAILED: none of the $handshake_count completed session(s) used AES_256_GCM."
        echo "observed completed handshakes (the suite name is at the end of each line):"
        grep -h -F "$HANDSHAKE_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
        echo "a XCHACHA20_POLY1305 suite above means the client fell back to the fallback suite"
        echo "instead of using the AES-256-GCM suite both configurations ask for."
        echo "help: check that server_aes_udp.json sets cipherSuites to CIPHER_SUITE_AES_256_GCM,"
        echo "help: that client_aes_udp.json sets profiles[0].cipherSuites and \"loggingLevel\": \"DEBUG\","
        echo "help: and that the log doesn't contain 'no common cipher suite with the server, the client offered'."
        print_client_log_tail 80
        print_client_log
        exit 1
    fi

    if [[ "$packet_count" -eq 0 ]]; then
        echo "transport assertion FAILED: no session ran over the UDP transport, so this test didn't"
        echo "verify AES-256-GCM over UDP. client_aes_udp.json must list only UDP port bindings,"
        echo "and server_aes_udp.json must bind the same UDP ports."
        print_client_log_tail 80
        print_client_log
        exit 1
    fi

    echo "cipher suite assertion passed: $aes_count session(s) negotiated AES_256_GCM."
    echo "transport assertion passed: $packet_count session(s) used the UDP transport."
    grep -h -F "$EXPECTED_AES_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
    grep -h -F "$PACKET_UNDERLAY_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
}

# Update server with the mixed config that only allows AES-256-GCM.
apply_server_config server_aes_udp.json

# Start the server daemon.
start_server

# Update client with the UDP config that offers AES-256-GCM.
apply_client_config client_aes_udp.json

# Start the client.
start_client

# Start testing.
sleep 2
echo ">>> socks5 UDP associate - AES-256-GCM over UDP <<<"
if ! ./socksudpclient -dst_host=127.0.0.1 -dst_port=9090 \
    -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
    -interval_ms=10 -num_request=100 -num_conn=60
then
    print_client_log
    echo "Test AES over UDP failed: the socks5 UDP associate data plane didn't carry the UDP packets."
    exit 1
fi

# The sessions used by the stage above must have negotiated AES-256-GCM over
# the UDP transport.
assert_aes_cipher_suite_over_udp

# The full client log is not dumped on success: with DEBUG level it is large,
# and the matching lines printed by the assertion are the evidence that the
# negotiated cipher suite and the transport were the expected ones.
print_client_log_tail 20

# Stop the client.
stop_client

# Stop the server daemon.
stop_server

delete_client_log

echo "AES over UDP test is successful."
