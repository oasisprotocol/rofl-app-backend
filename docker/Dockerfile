# Build stage
FROM golang:1.25-bookworm AS builder
WORKDIR /app

ARG OASIS_CLI_VERSION=0.16.0
# ARG OASIS_CLI_BRANCH=master

# Download or build oasis CLI.
RUN if [ "x${OASIS_CLI_BRANCH}" != "x" ]; then \
        git clone https://github.com/oasisprotocol/cli.git --depth 1 && \
		cd cli && git fetch origin ${OASIS_CLI_BRANCH} --depth 1 && \
		git checkout FETCH_HEAD && \
		make && mv oasis /oasis; \
	else \
		wget https://github.com/oasisprotocol/cli/releases/download/v${OASIS_CLI_VERSION}/oasis_cli_${OASIS_CLI_VERSION}_linux_amd64.tar.gz && \
		tar -zxvf oasis_cli_${OASIS_CLI_VERSION}_linux_amd64.tar.gz && \
		mv oasis_cli_${OASIS_CLI_VERSION}_linux_amd64/oasis /oasis; \
	fi

# Download and cache dependencies.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Build the binary.
COPY . ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o rofl-app ./

# Runner.
FROM golang:1.25-bookworm AS app

# Install minimal runtime dependencies
RUN apt-get update -qq && \
    apt-get install -y apt-transport-https ca-certificates \
	# Requirements for building OCI images.
	squashfs-tools cryptsetup-bin qemu-utils

# Copy the built binary from the builder stage
COPY --from=builder /app/rofl-app /app/backend
COPY --from=builder /oasis /usr/local/bin/oasis

ENTRYPOINT ["/app/backend"]
