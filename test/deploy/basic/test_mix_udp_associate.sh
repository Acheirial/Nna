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

# Replace server with mixed config.
./shadowlemon server replace config server_mix.json
if [[ "$?" -ne 0 ]]; then
    echo "command 'shadowlemon server replace config server_mix.json' failed"
    exit 1
fi
echo "server config:"
./shadowlemon server describe config

# Start the server daemon.
./shadowlemon server start
if [[ "$?" -ne 0 ]]; then
    echo "command 'shadowlemon server start' failed"
    exit 1
fi
server_status=$(./shadowlemon server status)
echo "server status:"
echo "$server_status"
if [[ "$server_status" != *RUNNING* ]]; then
    echo "server is not running"
    exit 1
fi

# Replace client with mixed config.
./shadowlemon client replace config client_mix.json
if [[ "$?" -ne 0 ]]; then
    echo "command 'shadowlemon client replace config client_mix.json' failed"
    exit 1
fi
sleep 1
./shadowlemon client export config simple
sleep 1
./shadowlemon client export config > client.url.txt
rm ~/.config/mieru/client.conf.pb
sleep 1
echo "client config before import:"
./shadowlemon client describe config
sleep 1
echo "client config URL:"
cat client.url.txt
sleep 1
./shadowlemon client import config "$(cat client.url.txt)"
echo "client config after import:"
./shadowlemon client describe config
sleep 1

# Start the client.
./shadowlemon client start
if [[ "$?" -ne 0 ]]; then
    echo "command 'shadowlemon client start' failed"
    exit 1
fi
client_status=$(./shadowlemon client status)
echo "client status:"
echo "$client_status"
if [[ "$client_status" != *RUNNING* ]]; then
    echo "client is not running"
    exit 1
fi

# Start testing.
sleep 1
echo ">>> socks5 UDP associate - TCP and UDP <<<"
./socksudpclient -dst_host=127.0.0.1 -dst_port=9090 \
  -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
  -interval_ms=10 -num_request=100 -num_conn=60
if [ "$?" -ne "0" ]; then
    print_client_log
    echo "Test UDP associate - TCP and UDP failed."
    exit 1
fi

# Stop the client.
./shadowlemon client stop
if [[ "$?" -ne 0 ]]; then
    echo "command 'shadowlemon client stop' failed"
    exit 1
fi
sleep 1
client_status=$(./shadowlemon client status)
echo "client status:"
echo "$client_status"
if [[ "$client_status" != *STOPPED* ]]; then
    echo "client is not stopped"
    exit 1
fi

# Stop the server daemon.
./shadowlemon server stop
if [[ "$?" -ne 0 ]]; then
    echo "command 'shadowlemon server stop' failed"
    exit 1
fi
sleep 1
server_status=$(./shadowlemon server status)
echo "server status:"
echo "$server_status"
if [[ "$server_status" != *STOPPED* ]]; then
    echo "server is not stopped"
    exit 1
fi

print_client_log
delete_client_log
sleep 1