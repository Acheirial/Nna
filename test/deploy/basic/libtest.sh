#!/bin/bash

# Copyright (C) 2022  mieru authors
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

function print_mieru_client_log() {
    echo "========== BEGIN OF MIERU CLIENT LOG =========="
    cat $HOME/.cache/mieru/*.log
    echo "==========  END OF MIERU CLIENT LOG  =========="
}

function delete_mieru_client_log() {
    rm -rf $HOME/.cache/mieru/*.log
}

# run_or_fail <command description> <command> [arguments...]
# Runs the command, and exits the test with the same exit code as the command
# when the command fails. Printing the command description is not possible by
# just checking "$?" after the command, because "set -e" aborts the script as
# soon as the command fails.
function run_or_fail() {
    local desc=$1
    shift
    local exit_code=0

    "$@" || exit_code=$?
    if [[ "$exit_code" -ne 0 ]]; then
        echo "command '$desc' failed"
        exit "$exit_code"
    fi
}

# apply_server_config <server config file>
function apply_server_config() {
    local config=$1

    run_or_fail "mita apply config $config" ./mita apply config "$config"
    echo "mieru server config:"
    ./mita describe config
}

# start_server
function start_server() {
    local server_status

    run_or_fail "mita start" ./mita start
    server_status=$(./mita status)
    echo "mieru server status:"
    echo "$server_status"
    if [[ "$server_status" != *RUNNING* ]]; then
        echo "mita server is not running"
        exit 1
    fi
}

# stop_server
function stop_server() {
    local server_status

    run_or_fail "mita stop" ./mita stop
    sleep 1
    server_status=$(./mita status)
    echo "mieru server status:"
    echo "$server_status"
    if [[ "$server_status" != *STOPPED* ]]; then
        echo "mita server is not stopped"
        exit 1
    fi
}

# apply_client_config <client config file>
function apply_client_config() {
    local config=$1

    run_or_fail "mieru apply config $config" ./mieru apply config "$config"
    echo "mieru client config:"
    ./mieru describe config
}

# start_client
function start_client() {
    local client_status

    run_or_fail "mieru start" ./mieru start
    client_status=$(./mieru status)
    echo "mieru client status:"
    echo "$client_status"
    if [[ "$client_status" != *RUNNING* ]]; then
        echo "mieru client is not running"
        exit 1
    fi
}

# stop_client
function stop_client() {
    local client_status

    run_or_fail "mieru stop" ./mieru stop
    sleep 1
    client_status=$(./mieru status)
    echo "mieru client status:"
    echo "$client_status"
    if [[ "$client_status" != *STOPPED* ]]; then
        echo "mieru client is not stopped"
        exit 1
    fi
}

# dump_client_log prints and deletes the mieru client log.
function dump_client_log() {
    print_mieru_client_log
    delete_mieru_client_log
    sleep 1
}

# run_socks5_new_conn <TCP|UDP>
function run_socks5_new_conn() {
    local label=$1

    sleep 2
    echo ">>> socks5 - new connections - $label <<<"
    if ! ./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
        -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
        -test_case=new_conn -num_request=3000
    then
        print_mieru_client_log
        echo "$label - test socks5 new_conn failed."
        exit 1
    fi
}

# run_socks5_reuse_conn <TCP|UDP>
function run_socks5_reuse_conn() {
    local label=$1

    sleep 1
    echo ">>> socks5 - reuse one connection - $label <<<"
    if ! ./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
        -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
        -test_case=reuse_conn -test_time_sec=30
    then
        print_mieru_client_log
        echo "$label - test socks5 reuse_conn failed."
        exit 1
    fi
}

# run_socks5_new_conn_no_wait <TCP|UDP>
function run_socks5_new_conn_no_wait() {
    local label=$1

    sleep 2
    echo ">>> socks5 - new connections - $label - handshake no wait <<<"
    if ! ./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
        -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
        -test_case=new_conn -num_request=3000
    then
        print_mieru_client_log
        echo "$label - test socks5 new_conn (handshake no wait) failed."
        exit 1
    fi
}

# run_socks5_test <TCP|UDP> <server config> <client config> <client config with handshake no wait>
# Runs all the socks5 test stages of test_tcp.sh and test_udp.sh. The only
# difference between these two tests is the configuration files, and the label
# used in the log output. The test exits with a non-zero code when any stage
# fails.
function run_socks5_test() {
    if [[ $# -ne 4 ]]; then
        echo "usage: run_socks5_test <TCP|UDP> <server config> <client config> <client config with handshake no wait>"
        exit 1
    fi
    local label=$1
    local server_config=$2
    local client_config=$3
    local client_no_wait_config=$4

    # Update mieru server with config.
    apply_server_config "$server_config"

    # Start mieru server proxy.
    start_server

    # Update mieru client with config.
    apply_client_config "$client_config"

    # Start mieru client.
    start_client

    # Start testing.
    run_socks5_new_conn "$label"
    run_socks5_reuse_conn "$label"

    # Stop mieru client.
    stop_client

    dump_client_log

    # Update mieru client with config handshake no wait mode.
    apply_client_config "$client_no_wait_config"

    # Start mieru client.
    start_client

    # Start testing.
    run_socks5_new_conn_no_wait "$label"

    # Stop mieru client.
    stop_client

    # Stop mieru server proxy.
    stop_server

    dump_client_log
}
