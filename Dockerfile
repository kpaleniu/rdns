# syntax=docker/dockerfile:1
#
# rdnsd in a container, in two stages: a full Rust toolchain to build it, and a
# runtime image holding three binaries, a licence, and nothing else.
#
# The half of this that is not obvious is the *readiness* half, and it is in
# `docker-compose`/Kubernetes rather than here: `/healthz` says the process is
# alive and `/readyz` says it holds every zone it is configured to answer for.
# A rolling restart that gates on the first one moves traffic to a secondary
# that has bound its sockets and transferred nothing. See README "Container
# image" and `rdns/src/readiness.rs`.

FROM rust:1.95-slim-bookworm AS build

# `ring` needs a C compiler. Nothing else: in particular **not git**, because
# nothing in this stage has a repository to ask — see `RDNS_GIT_DESCRIBE` below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Named rather than `COPY . .`, so what reaches this stage is the sources and the
# two manifests and nothing else. `rdnsr` is not built into this image, but cargo
# parses every workspace member's manifest and refuses one whose `src/main.rs` is
# missing, so it comes along.
COPY Cargo.toml Cargo.lock ./
COPY rdns rdns
COPY rdnsc rdnsc
COPY rdnsctl rdnsctl
COPY rdnsd rdnsd
COPY rdnsr rdnsr

# What `git describe` said, computed outside and passed in:
#
#     docker build --build-arg RDNS_GIT_DESCRIBE="$(git describe --always --dirty --tags)" .
#
# `rdns/build.rs` normally runs that itself, which would mean copying `.git` into
# the build context — and then every version of every file ever committed is one
# careless `COPY --from` or one `--target build` away from an image layer. A
# multi-stage build discarding the stage it landed in is a convention, not a
# guarantee. The cost of not doing it is that an image built without this arg
# reports a bare "0.1.0", which identifies nothing; `.dockerignore` says the same
# thing from the other side.
#
# Declared *after* the sources so that stamping a new commit does not invalidate
# the copy, and exported explicitly rather than relying on `ARG` reaching a
# `RUN`'s environment.
ARG RDNS_GIT_DESCRIBE=""
ENV RDNS_GIT_DESCRIBE=$RDNS_GIT_DESCRIBE

# Cache mounts rather than the usual "copy the manifests, build dummy crates,
# copy the real sources" dance: with five crates in the workspace that dance is
# five stub `main.rs`es to keep in step with five manifests, and it goes stale
# silently. BuildKit's cache does the same job with nothing to maintain.
#
# The binaries have to be copied out inside this same `RUN`, because a cache
# mount is not part of the resulting layer — `/src/target` does not exist any
# more once this instruction finishes.
#
# Only the three a server needs: `rdnsd` serves, `rdnsctl` asks it questions over
# the control socket, and `rdnsc` is a DNS client for `docker exec` when
# something is wrong and you want to ask from inside the network namespace.
# `rdnsr` is a resolver — a different service, and one an authoritative image has
# no business also being.
# `strip=debuginfo` undoes the workspace's `[profile.release] debug = 1`, which is
# there so a DHAT heap profile has `file:line` in its frame table. Nothing in this
# image can use that — the profiler is behind `--features dhat-heap`, which is not
# built here, and there are no sources to resolve frames against. Measured: 51 MB
# to 31 MB.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p rdnsd -p rdnsctl -p rdnsc \
        --config 'profile.release.strip="debuginfo"' \
    && mkdir -p /out \
    && cp target/release/rdnsd target/release/rdnsctl target/release/rdnsc /out/

FROM debian:bookworm-slim

# No `ca-certificates`: nothing here speaks TLS. The metrics endpoint is plain
# HTTP on purpose (bind it somewhere an operator reaches and a client does not),
# and DNS, AXFR and TSIG are all over port 53.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    # A fixed uid, and the same one distroless uses for `nonroot`, so a volume
    # chowned for this image works for the next one too. A name alone would be
    # resolved differently in every base image.
    && groupadd --gid 65532 rdns \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin rdns

COPY --from=build /out/rdnsd /out/rdnsctl /out/rdnsc /usr/local/bin/
# The one non-binary in the image. An image is a distribution of the software,
# and the MIT terms ask for the notice to travel with it.
COPY LICENSE /usr/share/licenses/rdns/LICENSE

# Config and keys are read; a secondary writes its transferred zones and the
# state sidecar. Owned by the runtime user so a bind mount inherits something
# sane, and 0750 on the keys because `rdnsd` refuses a world-readable secret and
# is right to.
RUN mkdir -p /etc/rdns/zones /etc/rdns/keys /run/rdns \
    && chown -R 65532:65532 /etc/rdns /run/rdns \
    && chmod 0750 /etc/rdns/keys /run/rdns

USER 65532:65532

# 5353, not 53, and it is not a compromise: an unprivileged process cannot bind
# 53, and the alternatives are worse than publishing a port. Running as root
# gives the whole server root for the sake of one syscall; a file capability
# baked into the image is invisible to `docker inspect` and is inherited by every
# image built FROM this one. Publish it instead — `-p 53:5353/udp -p 53:5353/tcp`
# — or, where the container needs 53 *inside* its own namespace (host
# networking, or a Kubernetes pod with hostNetwork), start it with
# `--sysctl net.ipv4.ip_unprivileged_port_start=53` and pass `--port 53`.
EXPOSE 5353/udp 5353/tcp 9153/tcp

# No `HEALTHCHECK`. It runs a command *inside* the container, which would mean
# shipping an HTTP client next to a DNS server to issue one GET — and every
# orchestrator that would schedule this probes over the network itself
# (Kubernetes `httpGet`, Nomad, ECS). The endpoints are there; what asks them is
# not this file's business. `docker run --health-cmd` is the escape hatch if you
# disagree, and it does not require the image to agree with you.

# SIGTERM is what Docker sends and what `rdnsd` handles: it stops accepting,
# finishes the work already accepted — an AXFR mid-stream included — and exits 0.
# The drain is bounded at 5s, so the default 10s `--stop-timeout` is ample.
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/rdnsd"]
# Overridable, and deliberately a *complete* command rather than a partial one:
# `docker run rdns --zone-dir /somewhere` replaces all of this, which is the
# behaviour that surprises nobody. 0.0.0.0 because a container's loopback is its
# own.
CMD ["--host", "0.0.0.0", "--port", "5353", \
     "--zone-dir", "/etc/rdns/zones", \
     "--metrics-listen", "0.0.0.0:9153"]
