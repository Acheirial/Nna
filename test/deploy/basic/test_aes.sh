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

# Test socks5 proxy with a configuration that forces the AES-256-GCM cipher
# suite. server_aes.json only allows CIPHER_SUITE_AES_256_GCM, and
# client_aes.json prefers it and falls back to CIPHER_SUITE_XCHACHA20_POLY1305,
# so a successful session must have negotiated AES-256-GCM.
#
# The negotiation result is only observable in a log line, and that line is
# written at DEBUG level by the client (pkg/protocol/session.go, message
# "<session> handshake completed with protocol version %d and cipher suite %v").
# client_aes.json therefore sets "loggingLevel": "DEBUG"; with the "INFO" level
# used by client_tcp.json the line is never emitted. The client writes its log
# to $HOME/.cache/mieru/<timestamp>_<pid>.log
# (pkg/log/mieru_client_logging.go, log.NewClientLogFile()).
#
# NOTE: only the client logs the negotiated suite. The server side
# (Session.acceptHandshake) logs nothing when the handshake succeeds; it only
# logs the reasons of a rejection, also at DEBUG level. server_aes.json is set
# to DEBUG as well so that a rejection is visible in the container output.
CLIENT_LOG_DIR="$HOME/.cache/mieru"
EXPECTED_AES_LINE="handshake completed with protocol version 2 and cipher suite AES_256_GCM"
HANDSHAKE_LINE="handshake completed with protocol version 2 and cipher suite"

# count_client_log_matches <substring>
# Prints how many lines of the mieru client log contain the given substring.
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

    echo "========== BEGIN TAIL OF MIERU CLIENT LOG =========="
    tail -n "$lines" "$CLIENT_LOG_DIR"/*.log 2>/dev/null || true
    echo "==========  END TAIL OF MIERU CLIENT LOG  =========="
}

# assert_aes_cipher_suite_negotiated
# Fails the test unless at least one established session logged that it used
# AES-256-GCM. An "apparently working" data plane is NOT enough: a silent
# fallback to CIPHER_SUITE_XCHACHA20_POLY1305 would still carry traffic, and
# this assertion is what tells the two cases apart.
function assert_aes_cipher_suite_negotiated() {
    local aes_count
    local handshake_count

    aes_count=$(count_client_log_matches "$EXPECTED_AES_LINE")
    handshake_count=$(count_client_log_matches "$HANDSHAKE_LINE")

    if [[ "$aes_count" -gt 0 ]]; then
        echo "cipher suite assertion passed: $aes_count session(s) negotiated AES_256_GCM."
        grep -h -F "$EXPECTED_AES_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
        return 0
    fi

    echo "cipher suite assertion FAILED: none of the $handshake_count completed session(s) used AES_256_GCM."
    if [[ "$handshake_count" -gt 0 ]]; then
        echo "the sessions completed the version 2 handshake with a different cipher suite."
        echo "observed completed handshakes (the suite name is at the end of each line):"
        grep -h -F "$HANDSHAKE_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
        echo "a XCHACHA20_POLY1305 suite above means the client fell back to the default suite"
        echo "instead of using the AES-256-GCM suite both configurations ask for."
    else
        echo "no client log line reports a completed version 2 handshake at all, so the"
        echo "session either wasn't established or the client didn't log at DEBUG level."
    fi
    echo "the expected log line is written by pkg/protocol/session.go:"
    echo "  log.Debugf(\"%v handshake completed with protocol version %d and cipher suite %v\", ...)"
    echo "help: check that server_aes.json sets cipherSuites to CIPHER_SUITE_AES_256_GCM,"
    echo "help: that client_aes.json sets profiles[0].cipherSuites and \"loggingLevel\": \"DEBUG\","
    echo "help: that the server allows a suite the client offers, and that the log doesn't"
    echo "help: contain 'no common cipher suite with the server, the client offered'."
    print_client_log_tail 80
    print_mieru_client_log
    exit 1
}

# Run the AES-256-GCM test over TCP.
apply_server_config server_aes.json
start_server
apply_client_config client_aes.json
start_client

# Data plane: run the same socks5 stages as test_tcp.sh.
run_socks5_new_conn TCP
run_socks5_reuse_conn TCP

# The sessions used by the stages above must have negotiated AES-256-GCM.
assert_aes_cipher_suite_negotiated

# The full client log is not dumped on success: with DEBUG level it is large,
# and the matching lines printed by the assertion are the evidence that the
# negotiated cipher suite was the expected one.
print_client_log_tail 20

stop_client
stop_server

delete_mieru_client_log

echo "AES test is successful."
