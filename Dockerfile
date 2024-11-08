# Stage 1: Build the Go app
FROM golang:1.23.3 AS builder

# Set up the working directory
WORKDIR /src

# Fetch Go dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
ENV GOCACHE=/root/.cache/go-build
ARG TARGETARCH
ARG LD_FLAGS
RUN --mount=type=cache,target="/root/.cache/go-build" GOOS=linux GOARCH=$TARGETARCH CGO_ENABLED=0 \
    go build -ldflags="$LD_FLAGS" -o oidc-apps-controller ./cmd/main.go

# Stage 2: Produce the runtime image
FROM gcr.io/distroless/static:nonroot AS oidc-apps-controller

# Copy the binary from the build stage
COPY --from=builder /src/oidc-apps-controller /bin/oidc-apps-controller

# Expose the port the app runs on
EXPOSE 10250

# Command to run the application
ENTRYPOINT ["/bin/oidc-apps-controller"]
