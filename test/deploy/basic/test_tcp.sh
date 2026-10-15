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

# Make sure this script has executable permission:
# git update-index --chmod=+x <file>

set -e

# Load test library.
source ./libtest.sh

# Update mieru server with TCP config.
./mita apply config server_tcp.json
if [[ "$?" -ne 0 ]]; then
    echo "command 'mita apply config server_tcp.json' failed"
    exit 1
fi
echo "mieru server config:"
./mita describe config

# Start mieru server proxy.
./mita start
if [[ "$?" -ne 0 ]]; then
    echo "command 'mita start' failed"
    exit 1
fi
server_status=$(./mita status)
echo "mieru server status:"
echo "$server_status"
if [[ "$server_status" != *RUNNING* ]]; then
    echo "mita server is not running"
    exit 1
fi

# Update mieru client with TCP config.
./mieru apply config client_tcp.json
if [[ "$?" -ne 0 ]]; then
    echo "command 'mieru apply config client_tcp.json' failed"
    exit 1
fi
echo "mieru client config:"
./mieru describe config

# Start mieru client.
./mieru start
if [[ "$?" -ne 0 ]]; then
    echo "command 'mieru start' failed"
    exit 1
fi
client_status=$(./mieru status)
echo "mieru client status:"
echo "$client_status"
if [[ "$client_status" != *RUNNING* ]]; then
    echo "mieru client is not running"
    exit 1
fi

# Start testing.
sleep 2
echo ">>> socks5 - new connections - TCP <<<"
./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
  -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
  -test_case=new_conn -num_request=3000
if [ "$?" -ne "0" ]; then
    print_mieru_client_log
    echo "TCP - test socks5 new_conn failed."
    exit 1
fi

sleep 1
echo ">>> socks5 - reuse one connection - TCP <<<"
./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
  -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
  -test_case=reuse_conn -test_time_sec=30
if [ "$?" -ne "0" ]; then
    print_mieru_client_log
    echo "TCP - test socks5 reuse_conn failed."
    exit 1
fi

# Stop mieru client.
./mieru stop
if [[ "$?" -ne 0 ]]; then
    echo "command 'mieru stop' failed"
    exit 1
fi
sleep 1
client_status=$(./mieru status)
echo "mieru client status:"
echo "$client_status"
if [[ "$client_status" != *STOPPED* ]]; then
    echo "mieru client is not stopped"
    exit 1
fi

print_mieru_client_log
delete_mieru_client_log
sleep 1

# Update mieru client with TCP config handshake no wait mode.
./mieru apply config client_tcp_no_wait.json
if [[ "$?" -ne 0 ]]; then
    echo "command 'mieru apply config client_tcp_no_wait.json' failed"
    exit 1
fi
echo "mieru client config:"
./mieru describe config

# Start mieru client.
./mieru start
if [[ "$?" -ne 0 ]]; then
    echo "command 'mieru start' failed"
    exit 1
fi
client_status=$(./mieru status)
echo "mieru client status:"
echo "$client_status"
if [[ "$client_status" != *RUNNING* ]]; then
    echo "mieru client is not running"
    exit 1
fi

# Start testing.
sleep 2
echo ">>> socks5 - new connections - TCP - handshake no wait <<<"
./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
  -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
  -test_case=new_conn -num_request=3000
if [ "$?" -ne "0" ]; then
    print_mieru_client_log
    echo "TCP - test socks5 new_conn (handshake no wait) failed."
    exit 1
fi

# Stop mieru client.
./mieru stop
if [[ "$?" -ne 0 ]]; then
    echo "command 'mieru stop' failed"
    exit 1
fi
sleep 1
client_status=$(./mieru status)
echo "mieru client status:"
echo "$client_status"
if [[ "$client_status" != *STOPPED* ]]; then
    echo "mieru client is not stopped"
    exit 1
fi

# Stop mieru server proxy.
./mita stop
if [[ "$?" -ne 0 ]]; then
    echo "command 'mita stop' failed"
    exit 1
fi
sleep 1
server_status=$(./mita status)
echo "mieru server status:"
echo "$server_status"
if [[ "$server_status" != *STOPPED* ]]; then
    echo "mita server is not stopped"
    exit 1
fi

print_mieru_client_log
delete_mieru_client_log
sleep 1
