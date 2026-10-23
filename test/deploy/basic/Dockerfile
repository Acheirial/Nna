# Copyright (C) 2021  mieru authors
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

# Assume this file is executed with `docker build -f` from the root dir of shadowlemon project.

FROM ubuntu:24.04

WORKDIR /test

# Copy binaries, data and test script into the container.
COPY bin/shadowlemon bin/httpserver bin/sockshttpclient bin/socksudpclient bin/udpserver \
    test/deploy/basic/client_mix.json test/deploy/basic/server_mix.json \
    test/deploy/basic/client_tcp.json test/deploy/basic/client_tcp_no_wait.json test/deploy/basic/server_tcp.json \
    test/deploy/basic/client_udp.json test/deploy/basic/client_udp_no_wait.json test/deploy/basic/server_udp.json \
    test/deploy/basic/client_aes.json test/deploy/basic/server_aes.json \
    test/deploy/basic/client_aes_udp.json test/deploy/basic/server_aes_udp.json \
    test/deploy/basic/client_suite_mismatch.json test/deploy/basic/server_suite_mismatch.json \
    test/deploy/basic/libtest.sh test/deploy/basic/test_mix_udp_associate.sh \
    test/deploy/basic/test_tcp.sh test/deploy/basic/test_udp.sh test/deploy/basic/test_aes.sh \
    test/deploy/basic/test_aes_udp.sh test/deploy/basic/test_suite_mismatch.sh \
    test/deploy/basic/test.sh /test/

# Create shadowlemon user and server config directory.
RUN /usr/sbin/useradd --no-create-home --user-group shadowlemon && \
    mkdir -p /etc/shadowlemon && \
    chown -R shadowlemon:shadowlemon /etc/shadowlemon && \
    chmod 775 /etc/shadowlemon && \
    mkdir -p /var/run/shadowlemon && \
    chown -R shadowlemon:shadowlemon /var/run/shadowlemon && \
    chmod 777 /var/run/shadowlemon

CMD ["/test/test.sh"]
