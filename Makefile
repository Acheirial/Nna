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
BENCH_TIME ?= 10s
FUZZ_TIME ?= 10s
BENCH_PACKAGES ?= ./pkg/cipher ./pkg/common ./pkg/protocol ./pkg/protocol/serveruser
FUZZ_PACKAGES ?= ./pkg/protocol

# With .ONESHELL, each recipe is executed in a single shell instance.
# This allows `cd` to affect subsequent commands in the same recipe.
# .ONESHELL is supported in GNU Make version 3.82 and later.
.ONESHELL:

# Build the mieru client and mita server binaries.
.PHONY: build
build: bin

# Build binaries.
.PHONY: bin
bin:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/mieru cmd/mieru/mieru.go
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/mita cmd/mita/mita.go

# Compile go libraries and run unit tests.
.PHONY: lib
lib: fmt vet
	CGO_ENABLED=0 go build -v ./...
	go clean -testcache
	go test -race -timeout=5m -coverprofile coverage.out ./...
	go tool cover -html coverage.out -o coverage.html

# Format source code.
.PHONY: fmt
fmt:
	CGO_ENABLED=0 go fmt ./...

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
	go clean -testcache
	CGO_ENABLED=0 go test -run='^$$' -bench=. -benchtime=${BENCH_TIME} ${BENCH_PACKAGES}

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

# Generate vendor directory.
.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor

# Build binaries used in integration tests.
.PHONY: test-binary
test-binary:
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags="-X 'github.com/enfein/mieru/v3/pkg/log.LogPrefix=C'" -o bin/mieru cmd/mieru/mieru.go
	CGO_ENABLED=0 go build -ldflags="-X 'github.com/enfein/mieru/v3/pkg/log.LogPrefix=S'" -o bin/mita cmd/mita/mita.go
	CGO_ENABLED=0 go build -o bin/httpserver test/cmd/httpserver/httpserver.go
	CGO_ENABLED=0 go build -o bin/sockshttpclient test/cmd/sockshttpclient/sockshttpclient.go
	CGO_ENABLED=0 go build -o bin/socksudpclient test/cmd/socksudpclient/socksudpclient.go
	CGO_ENABLED=0 go build -o bin/udpserver test/cmd/udpserver/udpserver.go

# Build docker images to run integration tests.
.PHONY: test-container-image
test-container-image: test-container-image-basic

.PHONY: test-container-image-basic
test-container-image-basic: $(TEST_BINARY_PREREQ)
	docker build -t mieru_basic:${SHORT_SHA} -f test/deploy/basic/Dockerfile .

# Run docker integration tests.
.PHONY: run-container-test
run-container-test: run-container-test-basic

.PHONY: run-container-test-prebuilt
run-container-test-prebuilt:
	$(MAKE) TEST_BINARY_PREREQ= run-container-test

.PHONY: run-container-test-basic
run-container-test-basic: test-container-image-basic
	docker run mieru_basic:${SHORT_SHA}

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
		--go_out="${ROOT}/pkg/appctl" --go_opt=module="github.com/enfein/mieru/v3/pkg/appctl" \
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
