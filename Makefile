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

ROOT=$(shell git rev-parse --show-toplevel)
SHORT_SHA=$(shell git rev-parse --short HEAD)
TEST_BINARY_PREREQ = test-binary
# Tag of the container image used by the integration tests. It can be overridden
# from the environment, e.g. by CI when the image is built by another tool.
TEST_CONTAINER_IMAGE ?= shadowlemon_basic:${SHORT_SHA}
BENCH_TIME ?= 10s
FUZZ_TIME ?= 10s
BENCH_PACKAGES ?= ./pkg/cipher ./pkg/common ./pkg/protocol ./pkg/protocol/serveruser
FUZZ_PACKAGES ?= ./pkg/cipher ./pkg/protocol

# With .ONESHELL, each recipe is executed in a single shell instance.
# This allows `cd` to affect subsequent commands in the same recipe.
# .ONESHELL is supported in GNU Make version 3.82 and later.
.ONESHELL:

# Build the shadowlemon binary. The single binary serves both the client
# (shadowlemon client <command>) and the server (shadowlemon server <command>).
.PHONY: build
build: bin

# Build binaries.
.PHONY: bin
bin:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/shadowlemon cmd/shadowlemon/main.go

# Compile go libraries and run unit tests.
.PHONY: lib
lib: fmt vet compile test

# Compile go libraries without running the tests.
.PHONY: compile
compile:
	CGO_ENABLED=0 go build -v ./...

# Run unit tests with the race detector and generate the coverage report.
# The race detector requires cgo, so CGO_ENABLED must be left at its default
# (i.e. 1 where a C toolchain is available) for this command.
# -count=1 disables the cached test results in GOCACHE, so a test result from a
# previous run can never hide a failure.
.PHONY: test
test:
	go test -race -count=1 -timeout=5m -coverprofile coverage.out ./...
	go tool cover -html coverage.out -o coverage.html

# Format source code.
.PHONY: fmt
fmt:
	CGO_ENABLED=0 go fmt ./...

# Verify that the source code is formatted. Unlike fmt, this fails instead of
# rewriting the files, so it can be used as a CI gate.
.PHONY: fmt-check
fmt-check:
	set -e
	unformatted=$$(gofmt -l .)
	if [ -n "$$unformatted" ]; then
		echo "gofmt would reformat the following files:"
		echo "$$unformatted"
		exit 1
	fi

# Run go vet.
.PHONY: vet
vet:
	CGO_ENABLED=0 go vet ./...

# Run golangci-lint.
.PHONY: lint
lint:
	golangci-lint run ./...

# Run benchmark.
.PHONY: bench
bench:
	CGO_ENABLED=0 go test -count=1 -run='^$$' -bench=. -benchtime=${BENCH_TIME} ${BENCH_PACKAGES}

# Run fuzz tests.
.PHONY: fuzz
fuzz:
	set -e
	for pkg in ${FUZZ_PACKAGES}; do
		fuzz_tests=$$(CGO_ENABLED=0 go test -list='^Fuzz' "$$pkg")
		for fuzz_test in $$fuzz_tests; do
			case "$$fuzz_test" in
				Fuzz*)
					echo "Running $$fuzz_test"
					CGO_ENABLED=0 go test -run='^$$' -fuzz="^$${fuzz_test}$$" -fuzztime=${FUZZ_TIME} "$$pkg"
					;;
			esac
		done
	done

# List the fuzz targets of FUZZ_PACKAGES as a JSON array, used to build the
# matrix of the fuzzing workflow. It fails when a package does not compile or
# when it has no fuzz target, so the matrix can never silently shrink.
# Example output: [{"pkg":"./pkg/protocol","target":"FuzzLowEntropyRoundTrip"}]
.PHONY: fuzz-matrix
fuzz-matrix:
	set -e
	printf '['
	first=1
	for pkg in ${FUZZ_PACKAGES}; do
		fuzz_tests=$$(CGO_ENABLED=0 go test -list='^Fuzz' "$$pkg" | grep '^Fuzz' || true)
		if [ -z "$$fuzz_tests" ]; then
			echo "no fuzz target found in $$pkg" >&2
			exit 1
		fi
		for fuzz_test in $$fuzz_tests; do
			if [ "$$first" -eq 0 ]; then
				printf ','
			fi
			first=0
			printf '{"pkg":"%s","target":"%s"}' "$$pkg" "$$fuzz_test"
		done
	done
	printf ']\n'

# Run a single fuzz target, used by the fuzzing workflow matrix.
# Example: make fuzz-one PKG=./pkg/protocol FUZZ=FuzzLowEntropyRoundTrip
.PHONY: fuzz-one
fuzz-one:
	set -e
	if [ -z "${PKG}" ] || [ -z "${FUZZ}" ]; then
		echo "usage: make fuzz-one PKG=<package> FUZZ=<fuzz target>"
		exit 1
	fi
	CGO_ENABLED=0 go test -run='^$$' -fuzz="^${FUZZ}$$" -fuzztime=${FUZZ_TIME} "${PKG}"

# Generate vendor directory.
.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor

# Build binaries used in integration tests.
.PHONY: test-binary
test-binary:
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/shadowlemon cmd/shadowlemon/main.go
	CGO_ENABLED=0 go build -o bin/httpserver test/cmd/httpserver/httpserver.go
	CGO_ENABLED=0 go build -o bin/sockshttpclient test/cmd/sockshttpclient/sockshttpclient.go
	CGO_ENABLED=0 go build -o bin/socksudpclient test/cmd/socksudpclient/socksudpclient.go
	CGO_ENABLED=0 go build -o bin/udpserver test/cmd/udpserver/udpserver.go

# Build docker images to run integration tests.
.PHONY: test-container-image
test-container-image: test-container-image-basic

.PHONY: test-container-image-basic
test-container-image-basic: $(TEST_BINARY_PREREQ)
	docker build -t $(TEST_CONTAINER_IMAGE) -f test/deploy/basic/Dockerfile .

# Run docker integration tests.
.PHONY: run-container-test
run-container-test: run-container-test-basic

.PHONY: run-container-test-prebuilt
run-container-test-prebuilt:
	$(MAKE) TEST_BINARY_PREREQ= run-container-test

.PHONY: run-container-test-basic
run-container-test-basic: test-container-image-basic
	docker run --rm $(TEST_CONTAINER_IMAGE)

# Run a single test script of the basic suite (test_tcp.sh, test_udp.sh or
# test_mix_udp_associate.sh) in an already built image, so that the scripts of
# test.sh can run as parallel CI jobs. The helper servers that test.sh starts
# are started here with the same timings.
# Example: make test-container-image-basic && make run-container-test-script TEST_SCRIPT=test_tcp.sh
.PHONY: run-container-test-script
run-container-test-script:
	set -e
	if [ -z "$(TEST_SCRIPT)" ]; then
		echo "usage: make run-container-test-script TEST_SCRIPT=<test script>"
		exit 1
	fi
	docker run --rm --entrypoint=/bin/bash $(TEST_CONTAINER_IMAGE) -c './httpserver & sleep 2; ./udpserver -port=9090 & sleep 1; exec ./$(TEST_SCRIPT)'

# Generate source code from protobuf.
# Call this after proto files are changed.
PROTOC_ARCH =
ifeq ($(shell uname -m), x86_64)
PROTOC_ARCH = amd64
endif
ifeq ($(shell uname -m), arm64)
PROTOC_ARCH = arm64
endif
.PHONY: protobuf
protobuf:
	# Download location: https://github.com/protocolbuffers/protobuf/releases
	if [ ! -x "${ROOT}/tools/build/protoc" ]; then
		curl -o "${ROOT}/tools/build/protoc" https://raw.githubusercontent.com/enfein/buildtools/main/protoc/33.5/linux_${PROTOC_ARCH}/bin/protoc
		chmod 755 "${ROOT}/tools/build/protoc"
	fi
	# Download location: https://github.com/protocolbuffers/protobuf-go/releases
	if [ ! -x "${ROOT}/tools/build/protoc-gen-go" ]; then
		curl -o "${ROOT}/tools/build/protoc-gen-go" https://raw.githubusercontent.com/enfein/buildtools/main/protoc-gen-go/1.36.11/linux_${PROTOC_ARCH}/protoc-gen-go
		chmod 755 "${ROOT}/tools/build/protoc-gen-go"
	fi

	PATH=${PATH}:"${ROOT}/tools/build" ${ROOT}/tools/build/protoc -I="${ROOT}/pkg" \
		--go_out="${ROOT}/pkg/appctl" --go_opt=module="github.com/Acheirial/shadowlemon/v3/pkg/appctl" \
		--proto_path="${ROOT}/pkg" \
		"${ROOT}/pkg/appctl/proto/base.proto" \
		"${ROOT}/pkg/appctl/proto/clientcfg.proto" \
		"${ROOT}/pkg/appctl/proto/servercfg.proto"

# Clean all the files outside the git repository.
.PHONY: clean
clean:
	git clean -fxd

# Clean go build cache.
.PHONY: clean-cache
clean-cache:
	go clean -cache
	go clean -testcache
