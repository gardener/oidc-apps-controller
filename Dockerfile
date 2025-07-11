# Stage 1: Build the Go app
FROM golang:1.24.5 AS builder

# Set up the working directory
WORKDIR /src

# Copy the source code into the container
COPY . .
RUN go mod download

# Build the application
RUN make build

# Stage 2: Produce the runtime image
FROM gcr.io/distroless/static:nonroot AS oidc-apps-controller

# Copy the binary from the build stage
COPY --from=builder /src/build/oidc-apps-controller /bin/oidc-apps-controller

# Expose the port the app runs on
EXPOSE 10250

# Command to run the application
ENTRYPOINT ["/bin/oidc-apps-controller"]
