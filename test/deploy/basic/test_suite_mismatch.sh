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

# Deployment level test of a cipher suite set mismatch: the server allows
# CIPHER_SUITE_AES_128_GCM only (server_suite_mismatch.json) and the client
# offers CIPHER_SUITE_XCHACHA20_POLY1305 only (client_suite_mismatch.json), so
# no session can ever be established.
#
# The expected outcome of this test is a FAILURE of the data plane, and the
# test passes when that failure is observed. Every assertion below is therefore
# a reverse assertion:
#
#   1. the socks5 client must fail instead of transferring data,
#   2. the client log must explain the failure with the "no common cipher suite
#      with the server, the client offered ..." message of pkg/protocol/session.go
#      and must NOT report a completed handshake,
#   3. both mita and mieru must still be RUNNING: a peer that offers a suite the
#      server doesn't allow is rejected per session, and must not take the
#      daemons down or leave a half established session behind.
#
# The reason of the rejection is only written to the client log at DEBUG level
# (pkg/protocol/mux.go logs the error of the underlay event loop), so
# client_suite_mismatch.json sets "loggingLevel": "DEBUG". The client writes its
# log to $HOME/.cache/mieru/<timestamp>_<pid>.log
# (pkg/log/mieru_client_logging.go, log.NewClientLogFile()).
CLIENT_LOG_DIR="$HOME/.cache/mieru"
NO_COMMON_SUITE_LINE="no common cipher suite with the server, the client offered"
HANDSHAKE_LINE="handshake completed with protocol version 3 and cipher suite"
# A mismatch must be rejected per session, right after the client sent its
# handshake request: an attempt that waits for the client handshake timeout
# means the client never saw the diagnostic response of the server.
HANDSHAKE_TIMEOUT_LINE="handshake timed out after"

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

# wait_for_client_log_match <substring> <max number of seconds to wait>
# The failed handshake is reported by a background goroutine, which may write
# the log line slightly after the socks5 client observed the failure. This waits
# for the line with a bounded number of retries, and returns 1 when the line
# never appears.
function wait_for_client_log_match() {
    local pattern=$1
    local remaining=$2

    while [[ "$remaining" -gt 0 ]]; do
        if [[ "$(count_client_log_matches "$pattern")" -gt 0 ]]; then
            return 0
        fi
        sleep 1
        remaining=$((remaining - 1))
    done
    return 1
}

# assert_daemon_running <mita|mieru> <daemon description>
function assert_daemon_running() {
    local cmd=$1
    local desc=$2
    local status

    if ! status=$(./"$cmd" status 2>&1); then
        status="./$cmd status failed: $status"
    fi
    echo "mieru $desc status:"
    echo "$status"
    if [[ "$status" != *RUNNING* ]]; then
        echo "mieru $desc is not running after the server rejected a handshake"
        echo "without a common cipher suite: the mismatch must be rejected per"
        echo "session instead of taking the daemon down."
        print_client_log_tail 80
        print_mieru_client_log
        exit 1
    fi
}

# Update mieru server with the config that only allows AES-128-GCM.
apply_server_config server_suite_mismatch.json

# Start mieru server proxy.
start_server

# Update mieru client with the config that only offers XCHACHA20-POLY1305.
apply_client_config client_suite_mismatch.json

# Start mieru client.
start_client

# Start testing. The socks5 connection MUST fail: no cipher suite is shared by
# the two configurations, so no session can be established, and every attempt
# fails right after the client sent its handshake request.
#
# The probe retries a connection that failed, so a permanent misconfiguration
# makes it run until "timeout" kills it: being killed is the expected outcome
# here, and the assertions below prove that each attempt still failed fast
# instead of waiting for the handshake timeout.
sleep 2
echo ">>> socks5 - new connections - no common cipher suite, failure is expected <<<"
probe_exit_code=0
timeout 20 ./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
    -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
    -test_case=new_conn -num_request=1 \
    || probe_exit_code=$?

if [[ "$probe_exit_code" -eq 0 ]]; then
    echo "the socks5 client transferred data although the server allows only"
    echo "CIPHER_SUITE_AES_128_GCM and the client offers only CIPHER_SUITE_XCHACHA20_POLY1305."
    echo "help: check that server_suite_mismatch.json sets cipherSuites to CIPHER_SUITE_AES_128_GCM"
    echo "help: and that client_suite_mismatch.json sets profiles[0].cipherSuites to CIPHER_SUITE_XCHACHA20_POLY1305."
    print_client_log_tail 80
    print_mieru_client_log
    exit 1
fi

echo "the socks5 client never transferred data (exit code $probe_exit_code), as expected."

# The failed handshake must be explained in the client log.
if ! wait_for_client_log_match "$NO_COMMON_SUITE_LINE" 10; then
    echo "the mieru client log doesn't explain why the handshake failed."
    echo "the expected log line is written by pkg/protocol/session.go:"
    echo "  fmt.Errorf(\"no common cipher suite with the server, the client offered %v\", suites)"
    echo "and reported by pkg/protocol/mux.go at DEBUG level."
    echo "help: check that client_suite_mismatch.json sets \"loggingLevel\": \"DEBUG\","
    echo "help: and that the server allows CIPHER_SUITE_AES_128_GCM while the client offers"
    echo "help: CIPHER_SUITE_XCHACHA20_POLY1305, so discovery succeeds but negotiation doesn't."
    print_client_log_tail 80
    print_mieru_client_log
    exit 1
fi

no_common_suite_count=$(count_client_log_matches "$NO_COMMON_SUITE_LINE")
echo "the client log reports the cipher suite mismatch $no_common_suite_count time(s):"
grep -h -F "$NO_COMMON_SUITE_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true

# No session may have been established.
handshake_count=$(count_client_log_matches "$HANDSHAKE_LINE")
if [[ "$handshake_count" -ne 0 ]]; then
    echo "cipher suite assertion FAILED: $handshake_count session(s) completed the version 2 handshake"
    echo "although the server and the client don't share a cipher suite:"
    grep -h -F "$HANDSHAKE_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
    print_client_log_tail 80
    print_mieru_client_log
    exit 1
fi
echo "cipher suite assertion passed: no session completed the handshake."

# Every attempt has to fail right after the handshake request, because the
# server answers each one with a diagnostic response. An attempt that waits for
# the handshake timeout means the client never saw that response.
handshake_timeout_count=$(count_client_log_matches "$HANDSHAKE_TIMEOUT_LINE")
if [[ "$handshake_timeout_count" -ne 0 ]]; then
    echo "cipher suite assertion FAILED: $handshake_timeout_count session(s) waited for the"
    echo "handshake timeout instead of observing the diagnostic response of the server,"
    echo "which rejects every open session request with status 2:"
    grep -h -F "$HANDSHAKE_TIMEOUT_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
    print_client_log_tail 80
    print_mieru_client_log
    exit 1
fi
echo "cipher suite assertion passed: no attempt waited for the handshake timeout."

# The rejected handshake must not affect the daemons.
assert_daemon_running mita "server"
assert_daemon_running mieru "client"

print_client_log_tail 20

# Stop mieru client.
stop_client

# Stop mieru server proxy.
stop_server

delete_mieru_client_log

echo "Cipher suite mismatch test is successful: the handshake was rejected and the daemons survived."
