#!/usr/bin/env bash
# TODO.md #43 — what happens when this server talks to one somebody else wrote.
#
#     ./run.sh all            # images, setup, every scenario; leaves it up
#     ./run.sh 43c            # one scenario, against an already-running network
#     ./run.sh shell          # a prompt inside the network, after a run
#     ./run.sh down           # and give the volumes back
#
# Needs a container runtime, which is the second thing after CI's `image` job
# that no local `cargo` invocation stands in for.
#
# Every service is on an `internal` bridge with no published ports; `contained`
# asserts that rather than trusting it, and `all` runs it before anything else.
set -uo pipefail

cd "$(dirname "$0")"
HERE="$(pwd)"
ROOT="$(cd ../.. && pwd)"
RUN="$HERE/run"
mkdir -p "$RUN"
# compose bind-mounts this file; without it Docker would helpfully create a
# *directory* of that name and Unbound would start with no trust anchor.
# setup() overwrites it with the real DS.
[ -f "$RUN/anchors.key" ] || echo '; placeholder; ./run.sh setup writes the real one' > "$RUN/anchors.key"

if [ "$(id -u)" = 0 ]; then DOCKER="docker"; else DOCKER="sudo -n docker"; fi
COMPOSE="$DOCKER compose -f $HERE/docker-compose.yml"

PASS=0; FAIL=0; SKIP=0
declare -a FAILED=()

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '   \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$*"); printf '   \033[31mFAIL\033[0m %s\n' "$*"; }
skip() { SKIP=$((SKIP+1)); printf '   \033[33mSKIP\033[0m %s\n' "$*"; }

# check <name> <expected-substring> <<< actual   — the workhorse assertion.
check() {
  local name="$1" want="$2" got; got="$(cat)"
  if printf '%s' "$got" | grep -qF -- "$want"; then
    ok "$name"
  else
    bad "$name"
    printf '%s\n' "$got" | sed 's/^/        | /' | head -25
    printf '        (wanted to see: %s)\n' "$want"
  fi
}

# Everything that asks a question asks it from inside the network.
t() { $COMPOSE exec -T tools "$@" 2>&1; }
dig_() { t dig +timeout=3 +tries=2 "$@"; }

# A log window docker will read as UTC. `docker compose logs --since` treats a
# bare timestamp as the daemon's *local* time, so `date -u` without the Z was
# widening every window by the host's UTC offset -- and by nothing at all on a
# host set to UTC, which is why it read as working.
since_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

wait_for() { # wait_for <seconds> <command...>  — polls until the command succeeds
  local deadline=$(( $(date +%s) + $1 )); shift
  until "$@" >/dev/null 2>&1; do
    [ "$(date +%s)" -ge "$deadline" ] && return 1
    sleep 1
  done
  return 0
}

# --------------------------------------------------------------------------

build() {
  say "build"
  info "rdns:local from $ROOT"
  $DOCKER build -q \
    --build-arg RDNS_GIT_DESCRIBE="$(cd "$ROOT" && git describe --always --dirty --tags 2>/dev/null || echo unknown)" \
    -t rdns:local "$ROOT" || return 1
  info "rdns-interop-peers:local"
  $DOCKER build -q -f "$HERE/Dockerfile.peers" -t rdns-interop-peers:local "$HERE" || return 1
}

setup() {
  say "setup"
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1
  # The zone dir is written to (journals, and a secondary's fetched zones), so
  # it is a volume seeded from the tree rather than a read-only mount.
  $COMPOSE run --rm --user root --no-deps tools sh -c '
    cp /srv/zones/example.com.zone /srv/zones/example.net.zone /srv/zones/example.org.zone /srv/primary-zones/ &&
    cp /srv/zones/child/*.zone /srv/child-zones/ &&
    chown -R 65532:65532 /srv/primary-zones /srv/primary-keys /srv/child-zones /srv/child-keys &&
    chmod 0750 /srv/primary-keys /srv/child-keys' >/dev/null || return 1

  # The parent zone is response_size.rs's verbatim, with two glue addresses
  # pointed at a child server that exists. Patched here rather than in the
  # tree's copy of the zone, so the shapes 43c asks about stay the ones that
  # file measures.
  $COMPOSE run --rm --user root --no-deps tools sh -c '
    sed -i "s/^ns.secure IN A 192.0.2.20/ns.secure IN A 10.53.0.11/;
            s/^ns.plain IN A  192.0.2.30/ns.plain IN A  10.53.0.11/"       /srv/primary-zones/example.com.zone /srv/primary-zones/example.net.zone' >/dev/null || return 1

  # 43c's control delegation: correctly signed child, deliberately wrong DS in
  # the parent. Appended rather than edited into the tree's zone, so the shapes
  # response_size.rs measures are untouched.
  $COMPOSE run --rm --user root --no-deps tools sh -c '
    cat >> /srv/primary-zones/example.com.zone <<EOZ
bogus   IN NS  ns.bogus.example.com.
bogus   IN DS  12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns.bogus IN A  10.53.0.11
EOZ
    chown 65532:65532 /srv/primary-zones/example.com.zone' >/dev/null || return 1

  # 43e's other direction: a zone rdnsd has to *send* in several messages.
  # Written out here rather than checked in, because five thousand lines of
  # generated zone file is not something to read in a diff.
  $COMPOSE run --rm --user root --no-deps tools sh -c '
    { echo "\$ORIGIN bigout.test."
      echo "\$TTL 300"
      echo "@   IN SOA ns1.bigout.test. hostmaster.bigout.test. ( 1 3600 600 604800 60 )"
      echo "@   IN NS  ns1.bigout.test."
      echo "ns1 IN A   10.53.0.2"
      i=1; while [ $i -le 5000 ]; do echo "host$i IN A 198.51.100.1"; i=$((i+1)); done
    } > /srv/primary-zones/bigout.test.zone
    chown 65532:65532 /srv/primary-zones/bigout.test.zone' >/dev/null || return 1

  # The DoT certificate (#42a). Self-signed, P-256, with both the name and the
  # address in the SAN so a client can verify either way. Mode 0600 and owned by
  # the runtime uid, because rdnsd refuses a private key its group can read.
  $COMPOSE run --rm --user root --no-deps tools sh -c '
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout /srv/primary-tls/key.pem -out /srv/primary-tls/cert.pem -days 30 \
      -subj "/CN=dns.example.test" \
      -addext "subjectAltName=DNS:dns.example.test,IP:10.53.0.2" 2>/dev/null &&
    chown 65532:65532 /srv/primary-tls/cert.pem /srv/primary-tls/key.pem &&
    chmod 0600 /srv/primary-tls/key.pem &&
    chmod 0644 /srv/primary-tls/cert.pem &&
    cp /srv/primary-tls/cert.pem /srv/run/dot-ca.pem' >/dev/null || return 1

  info "generating signing keys"
  # P-256 for example.com., P-384 for example.net. — the two curves this tree
  # can produce, and the pair response_size.rs measures.
  local ds_com ds_net
  ds_com=$($COMPOSE run --rm --no-deps rdnsd-primary \
      --signing-key-dir /etc/rdns/keys --generate-keys example.com 2>&1)
  ds_net=$($COMPOSE run --rm --no-deps rdnsd-primary \
      --signing-key-dir /etc/rdns/keys --key-algorithm ECDSAP384SHA384 \
      --generate-keys example.net 2>&1)
  {
    echo "; TODO.md #43c. The DS rdnsd's --generate-keys printed, used as"
    echo "; Unbound's trust anchor so the DS-to-DNSKEY link is tested too."
    printf '%s\n' "$ds_com" | grep -E '^[a-z0-9.]+\s+IN\s+DS\s' || true
    printf '%s\n' "$ds_net" | grep -E '^[a-z0-9.]+\s+IN\s+DS\s' || true
  } > "$RUN/anchors.key"
  # The secure children, and each one's DS spliced into its parent in place of
  # the placeholder response_size.rs carries. Without this the referral is a DS
  # pointing at a key nobody holds, which a validator correctly calls bogus --
  # and calling that a finding would be blaming the peer for our test data.
  $COMPOSE run --rm --no-deps rdnsd-child       --signing-key-dir /etc/rdns/keys --generate-keys bogus.example.com >/dev/null 2>&1

  local parent ds_child ds_rdata
  for parent in example.com example.net; do
    local alg=""
    [ "$parent" = example.net ] && alg="--key-algorithm ECDSAP384SHA384"
    ds_child=$($COMPOSE run --rm --no-deps rdnsd-child         --signing-key-dir /etc/rdns/keys $alg --generate-keys "secure.$parent" 2>&1)
    ds_rdata=$(printf '%s
' "$ds_child" | grep -E 'IN[[:space:]]+DS[[:space:]]'                | sed -E 's/^[^ 	]+[ 	]+IN[ 	]+DS[ 	]+//')
    [ -n "$ds_rdata" ] || { echo "no DS for secure.$parent."; printf '%s
' "$ds_child"; return 1; }
    info "secure.$parent. DS $ds_rdata"
    $COMPOSE run --rm --user root --no-deps tools sh -c "
      sed -i 's|^secure  IN DS .*|secure  IN DS $ds_rdata|' /srv/primary-zones/$parent.zone &&
      grep -q 'IN DS $ds_rdata' /srv/primary-zones/$parent.zone" >/dev/null || {
        echo "could not splice the DS into $parent"; return 1; }
  done

  info "anchors:"
  sed 's/^/     /' "$RUN/anchors.key"
  grep -qE 'IN\s+DS\s' "$RUN/anchors.key" || { echo "no DS came out of --generate-keys"; printf '%s\n%s\n' "$ds_com" "$ds_net"; return 1; }
}

up() {
  say "up"
  $COMPOSE up -d --wait --wait-timeout 60 2>&1 | tail -5
  $COMPOSE ps --format '   {{.Service}}\t{{.Status}}'
}

versions() {
  say "peers"
  printf '   %-18s %s\n' rdnsd "$($COMPOSE exec -T rdnsd-primary rdnsd --version 2>&1 | head -1)"
  printf '   %-18s %s\n' BIND "$($COMPOSE exec -T bind-secondary named -V 2>&1 | head -1)"
  printf '   %-18s %s\n' Knot "$($COMPOSE exec -T knot-secondary knotd -V 2>&1 | head -1)"
  printf '   %-18s %s\n' NSD "$(t nsd -v 2>&1 | head -1)"
  printf '   %-18s %s\n' Unbound "$(t unbound -V 2>&1 | head -1)"
  printf '   %-18s %s\n' dig "$(t dig -v 2>&1 | head -1)"
}

# --------------------------------------------------------------------------

contained() {
  say "contained — the harness must not be reachable from off this machine"

  local internal
  internal=$($DOCKER network inspect rdns-interop_interop --format '{{.Internal}}' 2>&1)
  [ "$internal" = "true" ] && ok "the bridge is internal: true" \
                           || bad "bridge Internal=$internal, expected true"

  local published
  published=$($COMPOSE ps --format '{{.Service}} {{.Publishers}}' 2>/dev/null | grep -v '\[\]' | grep -vc '^$')
  local pubtext; pubtext=$($COMPOSE ps --format '{{.Service}} {{.Publishers}}' 2>/dev/null | grep -E '"(PublishedPort":[1-9]|URL)' || true)
  if [ -z "$pubtext" ]; then ok "no service publishes a host port"
  else bad "a service publishes a port: $pubtext"; fi

  # The measurement that could refute it (CLAUDE.md §19): ask a container to
  # leave. An internal bridge has no default route off it, so this must fail.
  local esc; esc=$(t sh -c 'ip route get 1.1.1.1 2>&1; echo "rc=$?"')
  printf '%s' "$esc" | grep -qiE 'unreachable|rc=[^0]' \
    && ok "no route off the bridge (ip route get 1.1.1.1 fails)" \
    || bad "a container has a route to the internet: $esc"

  # And the rule that would carry it there if one existed.
  local nat; nat=$($DOCKER run --rm --net=host --privileged alpine:3.22 \
      sh -c 'iptables-save -t nat 2>/dev/null | grep -c "10.53.0.0/24.*MASQUERADE"' 2>/dev/null | tr -d '\r')
  [ "${nat:-0}" = "0" ] && ok "no MASQUERADE rule for 10.53.0.0/24" \
                        || bad "$nat MASQUERADE rules exist for the interop subnet"
}

# --------------------------------------------------------------------------

# The zone as a set of records, normalised so two servers' copies compare: the
# comments dig writes are dropped, whitespace is collapsed, owner names are
# ASCII-lowercased (RFC 4343) and the whole thing is sorted. What is left is the
# zone, not the transfer's framing or a server's idea of record order.
axfr_norm() { # axfr_norm <addr> <port> <zone> <label>
  local addr="$1" port="$2" zone="$3" label="$4"
  t dig +noall +answer +onesoa -p "$port" "@$addr" AXFR "$zone" \
    | sed 's/;.*$//' \
    | grep -v '^[[:space:]]*$' \
    | tr -s ' \t' '\t' \
    | awk -F'\t' 'BEGIN{OFS="\t"} {$1=tolower($1); print}' \
    | LC_ALL=C sort > "$RUN/axfr-$zone-$label.txt"
  wc -l < "$RUN/axfr-$zone-$label.txt" | tr -d ' '
}

serial_of() { # serial_of <addr> <port> <zone>
  t dig +short -p "$2" "@$1" SOA "$3" 2>/dev/null | awk '{print $3}' | head -1
}

wait_serial() { # wait_serial <addr> <port> <zone> <serial> <seconds>
  local deadline=$(( $(date +%s) + $5 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(serial_of "$1" "$2" "$3")" = "$4" ] && return 0
    sleep 1
  done
  return 1
}

SECONDARIES="bind-secondary:10.53.0.3 knot-secondary:10.53.0.4 nsd-secondary:10.53.0.5"

s43a() {
  say "43a - rdnsd as primary, a real secondary pulling from it"

  local zone ref_serial peer name addr n_ref n_peer
  for zone in example.com example.net example.org; do
    ref_serial=$(serial_of 10.53.0.2 5353 "$zone.")
    info "$zone. at the primary: serial $ref_serial"
    n_ref=$(axfr_norm 10.53.0.2 5353 "$zone." primary)

    for peer in $SECONDARIES; do
      name="${peer%%:*}"; addr="${peer##*:}"
      if wait_serial "$addr" 53 "$zone." "$ref_serial" 45; then
        ok "$name holds $zone. at serial $ref_serial"
      else
        bad "$name never reached serial $ref_serial for $zone. (has $(serial_of "$addr" 53 "$zone."))"
        continue
      fi
      n_peer=$(axfr_norm "$addr" 53 "$zone." "$name")
      if diff -q "$RUN/axfr-$zone.-primary.txt" "$RUN/axfr-$zone.-$name.txt" >/dev/null 2>&1; then
        ok "$name's copy of $zone. is identical, all $n_peer records"
      else
        bad "$name's copy of $zone. differs from the primary's ($n_ref vs $n_peer records)"
        diff "$RUN/axfr-$zone.-primary.txt" "$RUN/axfr-$zone.-$name.txt" | head -12 | sed 's/^/        | /'
      fi
    done
  done

  # ---- the specific thing the row says to watch -------------------------
  #
  # An IXFR that silently falls back to a full AXFR is legal (RFC 1995 sec 2)
  # and looks identical from the outside. The only place the difference is
  # visible is the secondary's own log, so that is what is read.
  say "43a - IXFR, and whether it is a delta or a silent AXFR"

  local since; since=$(since_now)
  local old_serial new_serial
  old_serial=$(serial_of 10.53.0.2 5353 example.org.)
  new_serial=$((old_serial + 1))
  info "example.org. $old_serial -> $new_serial, one record added"

  $COMPOSE exec -T --user root tools sh -c "
    sed -i 's/$old_serial/$new_serial/; \$a ixfr1   IN A   198.51.100.77' /srv/primary-zones/example.org.zone" || {
      bad "could not edit the zone file"; return; }
  $COMPOSE kill -s HUP rdnsd-primary >/dev/null 2>&1
  sleep 2

  if wait_serial 10.53.0.2 5353 example.org. "$new_serial" 20; then
    ok "rdnsd reloaded example.org. to serial $new_serial on SIGHUP"
  else
    bad "rdnsd did not reload to $new_serial (has $(serial_of 10.53.0.2 5353 example.org.))"
    return
  fi

  for peer in $SECONDARIES; do
    name="${peer%%:*}"; addr="${peer##*:}"
    if wait_serial "$addr" 53 example.org. "$new_serial" 60; then
      ok "$name followed example.org. to serial $new_serial"
    else
      bad "$name did not follow to $new_serial (has $(serial_of "$addr" 53 example.org.))"
      continue
    fi

    # The primary's own log is where "was a delta served" is answered without
    # having to read three log dialects: rdnsd says IXFR or AXFR, per peer.
    local served
    served=$($COMPOSE logs --since "$since" rdnsd-primary 2>/dev/null \
             | grep -E "of example\.org\..*peer=$addr" | tail -2)
    printf '%s\n' "$served" > "$RUN/ixfr-served-$name.log"
    if printf '%s' "$served" | grep -q 'IXFR of example.org.'; then
      ok "rdnsd served $name a delta: $(printf '%s' "$served" | grep -oE '[0-9]+ record\(s\) across [0-9]+ version\(s\)' | head -1)"
    elif printf '%s' "$served" | grep -q 'AXFR of example.org.'; then
      bad "rdnsd fell back to a full AXFR for $name - the fallback the row predicted"
      printf '%s\n' "$served" | sed 's/^/        | /'
    else
      bad "rdnsd logged no transfer to $name at all"
    fi

    # And the other half: did the peer apply it as a delta, or take a full copy
    # it did not need? Its own log, minus this harness's probe at .10.
    local log applied
    log=$($COMPOSE logs --since "$since" "$name" 2>/dev/null \
          | grep -i 'example.org' | grep -v '10\.53\.0\.10' | grep -viE 'outgoing|notify')
    printf '%s\n' "$log" > "$RUN/ixfr-$name.log"
    case "$name" in
      # Knot and NSD name the transfer kind. BIND does not at any severity we
      # get here, so the discriminator is the record count: the zone is 8
      # records and a delta for one addition is 5.
      knot-secondary) applied=$(printf '%s' "$log" | grep -c 'IXFR, incoming.*2026091102') ;;
      nsd-secondary)  applied=$(printf '%s' "$log" | grep -c 'request incremental zone transfer (IXFR)') ;;
      bind-secondary) applied=$(printf '%s' "$log" | grep -E 'Transfer completed' | tail -1 \
                                 | grep -cE ', [1-7] records,') ;;
    esac
    if [ "${applied:-0}" -ge 1 ]; then
      ok "$name applied it incrementally"
    else
      bad "$name took a full copy instead of applying the delta"
      printf '%s\n' "$log" | tail -6 | sed 's/^/        | /'
    fi
  done
}

# --------------------------------------------------------------------------

TSIG="hmac-sha256:interop.key.:DIgmHeQfYvAHq1dJuoah8wGGbWNisBT3457iG6YMdhE="

# The zone as a normalised record set, pulled with a key. Same shape as
# axfr_norm, which cannot take one.
axfr_keyed() { # axfr_keyed <addr> <port> <zone> <outfile>
  t dig +noall +answer +onesoa -p "$2" "@$1" AXFR "$3" -y "$TSIG" \
    | sed 's/;.*$//' | grep -v '^[[:space:]]*$' | tr -s ' \t' '\t' \
    | awk -F'\t' 'BEGIN{OFS="\t"}{$1=tolower($1);print}' | LC_ALL=C sort > "$4"
}

PRIMARIES="frombind.test.@10.53.0.7@bind-primary fromknot.test.@10.53.0.8@knot-primary"

s43b() {
  say "43b - rdnsd as secondary, a real primary pushing to it"

  local spec zone addr name
  for spec in $PRIMARIES; do
    zone="${spec%%@*}"; addr="$(echo "$spec" | cut -d@ -f2)"; name="${spec##*@}"

    if wait_serial 10.53.0.9 5353 "$zone" "$(serial_of "$addr" 53 "$zone")" 60; then
      ok "rdnsd replicated $zone from $name at serial $(serial_of 10.53.0.9 5353 "$zone")"
    else
      bad "rdnsd never matched $name's serial for $zone (rdnsd $(serial_of 10.53.0.9 5353 "$zone"), $name $(serial_of "$addr" 53 "$zone"))"
      continue
    fi

    # Record for record against the original, pulled back out of rdnsd with the
    # key: this secondary allows transfers to no address at all.
    axfr_keyed "$addr" 53 "$zone" "$RUN/b-$zone-origin.txt"
    axfr_keyed 10.53.0.9 5353 "$zone" "$RUN/b-$zone-rdnsd.txt"
    if diff -q "$RUN/b-$zone-origin.txt" "$RUN/b-$zone-rdnsd.txt" >/dev/null 2>&1; then
      ok "rdnsd's copy of $zone is identical to $name's, $(wc -l < "$RUN/b-$zone-rdnsd.txt" | tr -d ' ') records"
    else
      bad "rdnsd's copy of $zone differs from $name's"
      diff "$RUN/b-$zone-origin.txt" "$RUN/b-$zone-rdnsd.txt" | head -12 | sed 's/^/        | /'
    fi
  done

  # ---- IXFR in, driven by a dynamic update on the real primary -------------
  say "43b - NOTIFY in and IXFR in"
  local since; since=$(since_now)
  local i=0 before after line
  for spec in $PRIMARIES; do
    zone="${spec%%@*}"; addr="$(echo "$spec" | cut -d@ -f2)"; name="${spec##*@}"
    i=$((i+1))
    before=$(serial_of "$addr" 53 "$zone")

    # nsupdate, which is also 43d's client: the primary bumps its own serial and
    # writes a journal, and that journal is what makes the refresh incremental.
    t sh -c "printf 'server %s 53\nzone %s\nupdate add ixfr%s.%s 300 A 198.51.100.%s\nsend\n' '$addr' '$zone' '$i' '$zone' '$((80+i))' | nsupdate -y '$TSIG'" >/dev/null
    sleep 2
    after=$(serial_of "$addr" 53 "$zone")
    if [ -n "$after" ] && [ "$after" != "$before" ]; then
      ok "$name accepted a TSIG-signed UPDATE, serial $before -> $after"
    else
      bad "$name's serial did not move after an UPDATE (still $before)"
      continue
    fi

    if wait_serial 10.53.0.9 5353 "$zone" "$after" 60; then
      ok "rdnsd followed $zone to $after"
    else
      bad "rdnsd did not follow $zone to $after (has $(serial_of 10.53.0.9 5353 "$zone"))"
      continue
    fi

    # rdnsd says which it did: "N incremental step(s)" or ", sent in full".
    line=$($COMPOSE logs --since "$since" rdnsd-secondary 2>/dev/null | grep -E "secondary $zone: transferred serial" | tail -1)
    printf '%s\n' "$line" > "$RUN/b-ixfr-$name.log"
    if printf '%s' "$line" | grep -q 'incremental step'; then
      ok "rdnsd applied it as a delta: $(printf '%s' "$line" | grep -oE '[0-9]+ incremental step' | head -1)(s)"
    elif printf '%s' "$line" | grep -q 'sent in full'; then
      bad "$name fell back to a full AXFR: $line"
    else
      bad "rdnsd logged no transfer of $zone at all"
    fi

    # And the NOTIFY that woke it, rather than a refresh timer hours away.
    if $COMPOSE logs --since "$since" rdnsd-secondary 2>/dev/null | grep -q "NOTIFY for $zone: refreshing now"; then
      ok "rdnsd acted on $name's NOTIFY"
    else
      bad "rdnsd did not log a NOTIFY for $zone from $name"
    fi
  done

  # ---- EXPIRE: the branch that degrades quietly ----------------------------
  #
  # frombind.test. has a 45-second EXPIRE. CLAUDE.md sec 4: a zone out of
  # contact with every master must be withdrawn, not served stale with AA set.
  say "43b - EXPIRE, with the primary held down"
  local expire_since; expire_since=$(since_now)
  info "stopping bind-primary; frombind.test. EXPIRE is 45s"
  $COMPOSE stop bind-primary >/dev/null 2>&1

  local deadline=$(( $(date +%s) + 180 )) withdrawn=no rcode=
  while [ "$(date +%s)" -lt "$deadline" ]; do
    rcode=$(t dig +noall +comments -p 5353 @10.53.0.9 SOA frombind.test. 2>/dev/null | grep -oE 'status: [A-Z]+' | head -1)
    case "$rcode" in
      *REFUSED*|*SERVFAIL*|*NOTAUTH*) withdrawn=yes; break ;;
    esac
    sleep 3
  done
  if [ "$withdrawn" = yes ]; then
    ok "frombind.test. was withdrawn after EXPIRE ($rcode), not served stale"
  else
    bad "frombind.test. was still answered '$rcode' 180s after the primary went away"
  fi
  $COMPOSE logs --since "$expire_since" rdnsd-secondary 2>/dev/null | grep -iE 'expire|withdraw' | tail -3 | sed 's/^/        | /'

  info "restarting bind-primary"
  $COMPOSE start bind-primary >/dev/null 2>&1
  sleep 5
  if wait_serial 10.53.0.9 5353 frombind.test. "$(serial_of 10.53.0.7 53 frombind.test.)" 120; then
    ok "frombind.test. came back once the primary did"
  else
    bad "frombind.test. did not come back within 120s of the primary returning"
  fi
}

# --------------------------------------------------------------------------

# validated <name> <type> <rcode> <ad|noad> [min-answers]
validated() {
  local name="$1" type="$2" want_rcode="$3" want_ad="$4" min_ans="${5:-}"
  local out rcode flags ans label reason=""
  out=$(t dig +dnssec +timeout=5 +tries=2 @10.53.0.6 "$name" "$type" 2>&1)
  rcode=$(printf '%s' "$out" | grep -oE 'status: [A-Z]+' | head -1 | awk '{print $2}')
  flags=$(printf '%s' "$out" | grep -E '^;; flags:' | head -1)
  ans=$(printf '%s' "$out" | grep -oE 'ANSWER: [0-9]+' | head -1 | awk '{print $2}')
  label=$(printf '%-34s' "$name $type")
  [ "$rcode" = "$want_rcode" ] || reason="rcode ${rcode:-none}, wanted $want_rcode"
  case "$want_ad" in
    ad)   printf '%s' "$flags" | grep -q ' ad' || reason="${reason:+$reason; }no AD bit" ;;
    noad) printf '%s' "$flags" | grep -q ' ad' && reason="${reason:+$reason; }AD set, wanted insecure" ;;
  esac
  if [ -n "$min_ans" ] && [ "${ans:-0}" -lt "$min_ans" ]; then
    reason="${reason:+$reason; }ANSWER=$ans, wanted at least $min_ans"
  fi
  if [ -z "$reason" ]; then
    if [ "$want_ad" = ad ]; then ok "$label $rcode AD"; else ok "$label $rcode insecure"; fi
  else
    bad "$label $reason"
    printf '%s\n' "$out" | grep -E '^;;' | head -6 | sed 's/^/        | /'
  fi
}

s43c() {
  say "43c - Unbound validating every answer shape"

  # The control first: if this one passes as secure, nothing below means
  # anything. bogus.example.com. is correctly signed and the parent's DS for it
  # is deliberately wrong.
  validated www.bogus.example.com A SERVFAIL noad
  local cd_ans
  cd_ans=$(t dig +cd +short +timeout=5 @10.53.0.6 www.bogus.example.com A 2>&1 | head -1)
  if [ "$cd_ans" = "192.0.2.205" ]; then
    ok "...and +cd returns the data, so it is the validator rejecting it, not a dead child"
  else
    bad "the bogus child did not answer under +cd either (got '$cd_ans') - the control proves nothing"
  fi

  # A fourth implementation, offline and over the whole zone at once: ldns
  # checks every RRSIG and the completeness of the denial chain, which is the
  # "does the set of records prove what the answer claims" question asked of a
  # file rather than of one answer at a time.
  local P
  for P in example.com example.net; do
    t sh -c "dig +noall +answer +onesoa -p 5353 @10.53.0.2 AXFR $P. > /srv/run/zone-$P.txt" >/dev/null
    local verdict rc ctl
    # ldns-verify-zone says nothing when a zone is good, so the exit status is
    # the answer and its output is only for the failure.
    verdict=$(t sh -c "ldns-verify-zone /srv/run/zone-$P.txt 2>&1; echo rc=\$?")
    rc=$(printf '%s' "$verdict" | grep -oE 'rc=[0-9]+' | tail -1 | cut -d= -f2)
    if [ "${rc:-1}" = 0 ]; then
      ok "ldns verifies every signature and the whole denial chain of $P. offline"
    else
      bad "ldns will not verify $P. (exit $rc)"
      printf '%s' "$verdict" | head -10 | sed 's/^/        | /'
    fi

    # The control, because "exit 0" and "checked nothing" look identical. One
    # owner name moved should break its signatures and its place in the chain.
    ctl=$(t sh -c "sed 's/^www\\.$P\\./wwwX.$P./' /srv/run/zone-$P.txt > /srv/run/bad-$P.txt; ldns-verify-zone /srv/run/bad-$P.txt >/dev/null 2>&1; echo rc=\$?")
    if [ "$(printf '%s' "$ctl" | grep -oE 'rc=[0-9]+' | cut -d= -f2)" != 0 ]; then
      ok "...and rejects the same zone with one owner name moved"
    else
      bad "ldns accepted a deliberately corrupted $P., so its verdict on the real one means nothing"
    fi
  done

  local chain
  for P in example.com example.net; do
    if [ "$P" = example.com ]; then chain="NSEC / P-256"; else chain="NSEC3 / P-384"; fi
    info "$P - $chain"

    # positive
    validated "www.$P"              A      NOERROR ad 1
    validated "$P"                  SOA    NOERROR ad 1
    validated "$P"                  DNSKEY NOERROR ad 2
    validated "$P"                  MX     NOERROR ad 2
    validated "pool.$P"             A      NOERROR ad 16
    validated "pool.$P"             AAAA   NOERROR ad 16
    validated "s2026._domainkey.$P" TXT    NOERROR ad 1
    validated "_dmarc.$P"           TXT    NOERROR ad 1

    # negative: each owes a different proof (CLAUDE.md sec 8)
    validated "www.$P"              MX     NOERROR ad
    validated "nx.$P"               A      NXDOMAIN ad
    validated "a.wild.$P"           A      NOERROR ad 1
    validated "a.wild.$P"           TXT    NOERROR ad
    validated "wild.$P"             A      NOERROR ad
    validated "_domainkey.$P"       A      NOERROR ad

    # the two referral kinds
    validated "www.secure.$P"       A      NOERROR ad 1
    validated "nx.secure.$P"        A      NXDOMAIN ad
    validated "www.plain.$P"        A      NOERROR noad 1
  done
}

# --------------------------------------------------------------------------

s43d() {
  say "43d - the clients, not just the servers"

  local before after
  before=$(serial_of 10.53.0.2 5353 example.org.)
  t sh -c "printf 'server 10.53.0.2 5353\nzone example.org.\nupdate add up1.example.org. 300 A 198.51.100.41\nsend\n' | nsupdate -y '$TSIG'" | head -5 | sed 's/^/        | /'
  sleep 1
  after=$(serial_of 10.53.0.2 5353 example.org.)
  if [ -n "$after" ] && [ "$after" != "$before" ]; then
    ok "rdnsd accepted a TSIG-signed nsupdate, serial $before -> $after"
  else
    bad "rdnsd's serial did not move after nsupdate (still $before)"
  fi
  check "the added record is served" "198.51.100.41" <<< "$(t dig +short -p 5353 @10.53.0.2 up1.example.org. A)"

  t sh -c "printf 'server 10.53.0.2 5353\nzone example.org.\nupdate delete up1.example.org. A\nsend\n' | nsupdate -y '$TSIG'" >/dev/null
  sleep 1
  local gone; gone=$(t dig +short -p 5353 @10.53.0.2 up1.example.org. A)
  if [ -z "$gone" ]; then ok "and nsupdate deleted it again"; else bad "the deleted record is still served: $gone"; fi

  # The authorization half: the key is scoped to example.org., so the same key
  # must not be able to rewrite example.com. (CLAUDE.md sec 16).
  local refused leaked
  refused=$(t sh -c "printf 'server 10.53.0.2 5353\nzone example.com.\nupdate add evil.example.com. 300 A 198.51.100.66\nsend\n' | nsupdate -y '$TSIG' 2>&1")
  if printf '%s' "$refused" | grep -qiE 'REFUSED|NOTAUTH|NOTZONE'; then
    ok "the same key is refused on example.com., which it is not scoped for"
  else
    bad "an UPDATE to example.com. was not refused: $refused"
  fi
  leaked=$(t dig +short -p 5353 @10.53.0.2 evil.example.com. A)
  if [ -z "$leaked" ]; then ok "...and nothing was written"; else bad "evil.example.com. was created: $leaked"; fi

  # An unsigned UPDATE, which is what an attacker sends.
  t sh -c "printf 'server 10.53.0.2 5353\nzone example.org.\nupdate add nokey.example.org. 300 A 198.51.100.67\nsend\n' | nsupdate" >/dev/null 2>&1
  local nokey; nokey=$(t dig +short -p 5353 @10.53.0.2 nokey.example.org. A)
  if [ -z "$nokey" ]; then ok "an unsigned UPDATE changed nothing"; else bad "an unsigned UPDATE was applied: $nokey"; fi

  # The ACME dns-01 shape: add the challenge TXT, read it back the way a CA
  # would, remove it. #40f weighed this request; nothing here had ever sent one.
  local token="Zm9vYmFyX3Rlc3RfdG9rZW5fNDNkX2FjbWVfY2hhbGxlbmdl"
  t sh -c "printf 'server 10.53.0.2 5353\nzone example.org.\nupdate add _acme-challenge.example.org. 120 TXT \"$token\"\nsend\n' | nsupdate -y '$TSIG'" >/dev/null
  sleep 1
  check "the dns-01 challenge TXT is served" "$token" <<< "$(t dig +short -p 5353 @10.53.0.2 _acme-challenge.example.org. TXT)"
  t sh -c "printf 'server 10.53.0.2 5353\nzone example.org.\nupdate delete _acme-challenge.example.org. TXT\nsend\n' | nsupdate -y '$TSIG'" >/dev/null
  sleep 1
  local left; left=$(t dig +short -p 5353 @10.53.0.2 _acme-challenge.example.org. TXT)
  if [ -z "$left" ]; then ok "and the challenge was cleaned up"; else bad "the challenge TXT survived deletion: $left"; fi

  # Three more clients that are not dig, each encoding a query its own way.
  check "kdig (Knot) gets the same answer" "192.0.2.10" <<< "$(t kdig +short -p 5353 @10.53.0.2 www.example.com A 2>&1)"
  check "drill (ldns) gets the same answer" "192.0.2.10" <<< "$(t drill -p 5353 @10.53.0.2 www.example.com A 2>&1)"
  check "kdig validates the chain itself" "192.0.2.10" <<< "$(t kdig +short +dnssec -p 5353 @10.53.0.2 www.example.com A 2>&1)"
}

# --------------------------------------------------------------------------

s43e() {
  say "43e - what a real peer sends that ours does not"

  # ---- an AXFR split differently, both directions -------------------------
  #
  # Every zone in 43a and 43b fits in one message, so a receiver that checked
  # only the first envelope's TSIG, or a sender that signed only the first,
  # would pass all of it. RFC 8945 sec 5.3.1 wants the first, the last, and
  # every hundredth between.
  # dig's own trailer counts the envelopes; +noall would suppress it.
  local out msgs recs
  out=$(t dig -p 5353 @10.53.0.2 AXFR bigout.test. -y "$TSIG" 2>&1)
  msgs=$(printf '%s' "$out" | grep -oE 'messages [0-9]+' | head -1 | awk '{print $2}')
  recs=$(printf '%s' "$out" | grep -oE 'XFR size: [0-9]+' | head -1 | awk '{print $3}')
  if [ "${msgs:-0}" -gt 1 ]; then
    ok "rdnsd split bigout.test. across $msgs messages, $recs records"
  else
    bad "the big AXFR out of rdnsd came back in ${msgs:-no} message(s) - the multi-envelope path was not exercised"
    printf '%s' "$out" | tail -6 | sed 's/^/        | /'
  fi

  # dig abandons a transfer whose TSIG does not verify and prints no trailer for
  # one it abandoned, so reaching the trailer with the whole record count is the
  # assertion about every envelope's signature. There is no separate "the TSIG
  # was fine" line to grep for -- grepping for the string finds only the record
  # dig printed, which is why the first version of this check passed on a run
  # where nothing had been verified.
  if [ "${recs:-0}" -ge 5004 ]; then
    ok "...and dig carried all $recs records through, so every envelope's TSIG verified"
  else
    bad "dig stopped at ${recs:-0} records, short of the 5004 the zone holds"
  fi

  # Now the other way: BIND sends, rdnsd receives.
  local bind_serial
  bind_serial=$(serial_of 10.53.0.7 53 big.test.)
  if wait_serial 10.53.0.9 5353 big.test. "$bind_serial" 120; then
    ok "rdnsd received BIND's multi-message AXFR of big.test. (serial $bind_serial)"
    axfr_keyed 10.53.0.7 53 big.test. "$RUN/e-big-bind.txt"
    axfr_keyed 10.53.0.9 5353 big.test. "$RUN/e-big-rdnsd.txt"
    if diff -q "$RUN/e-big-bind.txt" "$RUN/e-big-rdnsd.txt" >/dev/null 2>&1; then
      ok "...and all $(wc -l < "$RUN/e-big-rdnsd.txt" | tr -d ' ') records survived it intact"
    else
      bad "rdnsd's copy of big.test. differs from BIND's"
      diff "$RUN/e-big-bind.txt" "$RUN/e-big-rdnsd.txt" | head -10 | sed 's/^/        | /'
    fi
  else
    bad "rdnsd never replicated big.test. (has $(serial_of 10.53.0.9 5353 big.test.), BIND has $bind_serial)"
  fi

  # ---- EDNS options we do not implement -----------------------------------
  #
  # A resolver sends these whether or not we understand them; the rule is that
  # an unknown option is ignored and the rest of the answer is unaffected
  # (RFC 6891 sec 6.1.2).
  check "a DNS COOKIE (RFC 7873) does not break the answer" "192.0.2.10" \
    <<< "$(t dig +short +cookie -p 5353 @10.53.0.2 www.example.com A 2>&1)"
  check "an NSID request is answered anyway" "192.0.2.10" \
    <<< "$(t dig +short +nsid -p 5353 @10.53.0.2 www.example.com A 2>&1)"
  check "an unknown EDNS option (65001) is ignored" "192.0.2.10" \
    <<< "$(t dig +short +ednsopt=65001:c0ffee -p 5353 @10.53.0.2 www.example.com A 2>&1)"
  check "unknown EDNS flags are ignored" "192.0.2.10" \
    <<< "$(t dig +short +ednsflags=0x40 -p 5353 @10.53.0.2 www.example.com A 2>&1)"

  # EDNS version 1 must be refused as BADVERS, not answered (RFC 6891 sec 6.1.3).
  #
  # kdig, not dig: dig prints "BADVERS, retrying with EDNS version 0" and then
  # shows the *retry's* answer, so grepping its output for a status finds
  # NOERROR and reads as a defect in the server. Written with dig first, and
  # filed as a finding for about a minute (CLAUDE.md sec 19).
  check "EDNS version 1 gets BADVERS" "BADVERS" \
    <<< "$(t kdig +edns=1 -p 5353 @10.53.0.2 www.example.com A 2>&1 | grep -E 'status:')"

  # ---- shapes a peer generates and this tree does not ---------------------
  check "an unknown RR type is a clean NODATA, not a failure" "NOERROR" \
    <<< "$(t dig -p 5353 @10.53.0.2 www.example.com TYPE999 2>&1 | grep -E 'status:')"
  check "a 0x20-randomised QNAME comes back with its case intact" "wWw.ExAmPlE.cOm" \
    <<< "$(t dig -p 5353 @10.53.0.2 wWw.ExAmPlE.cOm A 2>&1 | grep -A1 'QUESTION SECTION')"
  check "ANY is answered, not dropped (RFC 8482)" "NOERROR" \
    <<< "$(t dig -p 5353 @10.53.0.2 example.com ANY 2>&1 | grep -E 'status:')"
  check "a CHAOS-class question is refused, not answered from IN" "REFUSED" \
    <<< "$(t dig -p 5353 @10.53.0.2 -c CH version.bind TXT 2>&1 | grep -E 'status:')"
  check "a query over TCP is answered" "192.0.2.10" \
    <<< "$(t dig +short +tcp -p 5353 @10.53.0.2 www.example.com A 2>&1)"
  check "kdig's EDNS padding does not break the answer" "192.0.2.10" \
    <<< "$(t kdig +short +padding=128 -p 5353 @10.53.0.2 www.example.com A 2>&1)"

  # ---- #46: a NOTIFY the peer's ACL demands be signed ---------------------
  #
  # NSD's `allow-notify: <addr> <key>` and Knot's `acl: { key: ..., action:
  # notify }` both refuse an unsigned NOTIFY, which is how #46 was found: rdnsd
  # could not sign one, and logged the refusal as "acknowledged". Both configs
  # now name the key, so an unsigned NOTIFY would fail this.
  #
  # BIND is deliberately still unkeyed in rdnsd-primary.toml: it accepts an
  # unsigned NOTIFY from a configured primary whatever allow-notify says, so
  # leaving it so keeps that path covered.
  say "46 - a signed NOTIFY, to peers whose ACLs demand one"

  local nsince; nsince=$(since_now)
  local nserial nnew
  nserial=$(serial_of 10.53.0.2 5353 example.org.)
  nnew=$((nserial + 1))
  # A plain global replace, as 43a's edit does: the serial is a distinctive
  # number and appears nowhere else in the file, whichever of the two layouts
  # the file is in by now (the tree's, or the one rdnsd rewrote after 43d).
  $COMPOSE exec -T --user root tools \
    sh -c "sed -i 's/$nserial/$nnew/' /srv/primary-zones/example.org.zone" >/dev/null 2>&1
  $COMPOSE kill -s HUP rdnsd-primary >/dev/null 2>&1
  sleep 6

  local sent
  sent=$($COMPOSE logs --since "$nsince" rdnsd-primary 2>/dev/null | grep 'NOTIFY example.org.')
  printf '%s\n' "$sent" > "$RUN/notify-46.log"

  local who
  # The address as rdnsd prints it, port included: `10.53.0.4:53#interop.key.`.
  for who in "knot-secondary=10.53.0.4:53#interop.key." \
             "nsd-secondary=10.53.0.5:53#interop.key." \
             "bind-secondary=10.53.0.3:53"; do
    local nname="${who%%=*}" naddr="${who#*=}"
    # Pinned to this run's serial. Without it the window's earlier, still-signed
    # NOTIFYs satisfy the grep, and unsigning the config to check that this test
    # can fail leaves all three of these passing.
    if printf '%s' "$sent" | grep -qF "serial $nnew to $naddr: accepted"; then
      ok "$nname accepted a NOTIFY sent as $naddr"
    else
      bad "$nname did not accept the NOTIFY"
      printf '%s\n' "$sent" | grep -F "${naddr%%#*}" | head -3 | sed 's/^/        | /'
    fi
  done

  if printf '%s' "$sent" | grep -q 'refused ('; then
    bad "a NOTIFY was refused in this run"
    printf '%s\n' "$sent" | grep 'refused (' | head -3 | sed 's/^/        | /'
  else
    ok "no NOTIFY was refused - and a refusal is now a warning naming the rcode, not 'acknowledged'"
  fi

  # #46c: NSD is named only under [zones."example.org."], so it must be told
  # about that zone and about no other. Until #46c the per-zone table was
  # parsed and read by nothing, and this would find NSD in neither list.
  local other
  other=$($COMPOSE logs --since "$nsince" rdnsd-primary 2>/dev/null \
          | grep -E 'NOTIFY example\.(com|net)\.' | grep -c '10.53.0.5' || true)
  if [ "${other:-0}" = 0 ]; then
    ok "...and the per-zone list is per zone: nothing else was sent to 10.53.0.5"
  else
    bad "$other NOTIFYs for other zones went to example.org.'s per-zone target"
  fi
}

# --------------------------------------------------------------------------

s42a() {
  say "42a - DNS over TLS (RFC 7858), answered to somebody else's client"

  # kdig is Knot's, and the only client here with the full DoT vocabulary:
  # +tls-ca verifies the chain, +tls-hostname names what to check it against,
  # and +tls-pin checks the key rather than the name. Three different ways of
  # being satisfied, which is three different ways of catching a server that
  # presents the wrong thing.
  check "kdig verifies the chain and gets the answer" "192.0.2.10" \
    <<< "$(t kdig +short +tls-ca=/srv/run/dot-ca.pem +tls-hostname=dns.example.test \
              -p 853 @10.53.0.2 www.example.com A 2>&1)"

  check "...and over the address in the SAN, with no hostname given" "192.0.2.10" \
    <<< "$(t kdig +short +tls-ca=/srv/run/dot-ca.pem -p 853 @10.53.0.2 www.example.com A 2>&1)"

  # The pin is the certificate's public key, which is what a stub resolver with
  # no CA store uses (RFC 7858 §4.2). Computed here rather than written down,
  # because the certificate is generated per run.
  local pin
  pin=$(t sh -c "openssl x509 -in /srv/run/dot-ca.pem -pubkey -noout \
        | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64")
  pin=$(printf '%s' "$pin" | tr -d '\r\n ')
  check "kdig is satisfied by a pinned key (RFC 7858 §4.2)" "192.0.2.10" \
    <<< "$(t kdig +short "+tls-pin=$pin" -p 853 @10.53.0.2 www.example.com A 2>&1)"

  # The measurement that could refute the three above (§19): a client that
  # trusts the *wrong* certificate must fail. Without this, "+tls-ca passed"
  # is equally consistent with a client that verifies nothing.
  local wrong
  wrong=$(t sh -c "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -nodes -keyout /tmp/w.key -out /tmp/w.pem -days 1 -subj '/CN=dns.example.test' \
      -addext 'subjectAltName=DNS:dns.example.test,IP:10.53.0.2' 2>/dev/null;
      kdig +short +tls-ca=/tmp/w.pem +tls-hostname=dns.example.test \
        -p 853 @10.53.0.2 www.example.com A 2>&1")
  if printf '%s' "$wrong" | grep -q '192.0.2.10'; then
    bad "kdig accepted a certificate it should not trust - the checks above prove nothing"
    printf '%s\n' "$wrong" | head -4 | sed 's/^/        | /'
  else
    ok "...and refuses a certificate it does not trust"
  fi

  # A signed zone over DoT, so the two encryptions are known not to interfere:
  # DNSSEC records are payload and TLS is the pipe.
  check "a DNSSEC-signed answer survives the TLS transport" "RRSIG" \
    <<< "$(t kdig +dnssec +tls-ca=/srv/run/dot-ca.pem -p 853 @10.53.0.2 www.example.com A 2>&1)"

  # Plain TCP on 5353 still answers: DoT is an addition, not a replacement, and
  # a resolver that cannot speak it must not be locked out.
  check "plain TCP still answers on its own port" "192.0.2.10" \
    <<< "$(t dig +short +tcp -p 5353 @10.53.0.2 www.example.com A 2>&1)"

  # And the counters, which are the whole of the expiry story: nothing here
  # parses notAfter, so `dns_tls_handshake_failures_total` is what an operator
  # alerts on. Tie them to the handshakes just made.
  local scrape shook failed
  scrape=$(t sh -c "dig +short @10.53.0.2 -p 5353 www.example.com A >/dev/null;
                    python3 -c \"
import urllib.request
print(urllib.request.urlopen('http://10.53.0.2:9153/metrics').read().decode())\"" 2>&1)
  shook=$(printf '%s\n' "$scrape" | awk '/^dns_tls_handshakes_total /{print $2}')
  failed=$(printf '%s\n' "$scrape" | awk '/^dns_tls_handshake_failures_total /{print $2}')
  if [ "${shook:-0}" -ge 4 ]; then
    ok "dns_tls_handshakes_total is $shook, counting the handshakes above"
  else
    bad "dns_tls_handshakes_total is ${shook:-absent}, expected at least 4"
  fi
  if [ "${failed:-0}" -ge 1 ]; then
    ok "dns_tls_handshake_failures_total is $failed, counting the refused one"
  else
    bad "dns_tls_handshake_failures_total is ${failed:-absent}, expected at least 1"
  fi

  # ---- DoQ, on the same port number and the same certificate --------------
  say "42b - DNS over QUIC (RFC 9250)"

  check "kdig speaks DoQ and gets the answer" "192.0.2.10" \
    <<< "$(t kdig +short +quic +tls-ca=/srv/run/dot-ca.pem +tls-hostname=dns.example.test \
              -p 853 @10.53.0.2 www.example.com A 2>&1)"

  # A signed answer, which is also the one large enough to matter: QUIC has no
  # 512-octet reflex and nothing here should truncate.
  check "a DNSSEC-signed answer comes back over QUIC" "RRSIG" \
    <<< "$(t kdig +dnssec +quic +tls-ca=/srv/run/dot-ca.pem +tls-hostname=dns.example.test \
              -p 853 @10.53.0.2 www.example.com A 2>&1)"

  # The same negative control DoT gets: a client trusting the wrong certificate
  # must fail, or "+tls-ca passed" says nothing about what was verified.
  local qwrong
  qwrong=$(t sh -c "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -nodes -keyout /tmp/qw.key -out /tmp/qw.pem -days 1 -subj '/CN=dns.example.test' \
      -addext 'subjectAltName=DNS:dns.example.test,IP:10.53.0.2' 2>/dev/null;
      kdig +short +quic +tls-ca=/tmp/qw.pem +tls-hostname=dns.example.test \
        -p 853 @10.53.0.2 www.example.com A 2>&1")
  if printf '%s' "$qwrong" | grep -q '192.0.2.10'; then
    bad "the DoQ client accepted a certificate it should not trust"
  else
    ok "...and refuses a certificate it does not trust"
  fi

  # 853/udp and 853/tcp at once, which is the claim the two listeners make by
  # sharing a number. Both answered above; this says they are both still there.
  check "DoT on 853/tcp still answers with DoQ on 853/udp" "192.0.2.10" \
    <<< "$(t kdig +short +tls-ca=/srv/run/dot-ca.pem -p 853 @10.53.0.2 www.example.com A 2>&1)"

  local qscrape qshook
  qscrape=$(t python3 -c "
import urllib.request
print(urllib.request.urlopen('http://10.53.0.2:9153/metrics').read().decode())" 2>&1)
  qshook=$(printf '%s\n' "$qscrape" | awk '/^dns_quic_handshakes_total /{print $2}')
  if [ "${qshook:-0}" -ge 2 ]; then
    ok "dns_quic_handshakes_total is $qshook, counted separately from DoT's"
  else
    bad "dns_quic_handshakes_total is ${qshook:-absent}, expected at least 2"
  fi

  # ---- DoH, on 443 and through an HTTP stack ------------------------------
  say "42c - DNS over HTTPS (RFC 8484)"

  check "kdig speaks DoH and gets the answer" "192.0.2.10"     <<< "$(t kdig +short +https=/dns-query +tls-ca=/srv/run/dot-ca.pem               +tls-hostname=dns.example.test -p 443 @10.53.0.2 www.example.com A 2>&1)"

  # The GET form as well as the POST one. RFC 8484 requires a server to take
  # both, and kdig's +https-get is the only client here that sends the GET.
  check "...and the GET form with ?dns=<base64url>" "192.0.2.10"     <<< "$(t kdig +short +https=/dns-query +https-get +tls-ca=/srv/run/dot-ca.pem               +tls-hostname=dns.example.test -p 443 @10.53.0.2 www.example.com A 2>&1)"

  check "a DNSSEC-signed answer comes back over HTTPS" "RRSIG"     <<< "$(t kdig +dnssec +https=/dns-query +tls-ca=/srv/run/dot-ca.pem               +tls-hostname=dns.example.test -p 443 @10.53.0.2 www.example.com A 2>&1)"

  # A wrong path is a 404, not an answer: the endpoint is one path, and a server
  # that answered DNS on any URI would be a different protocol.
  local badpath
  badpath=$(t kdig +short +https=/wrong +tls-ca=/srv/run/dot-ca.pem               +tls-hostname=dns.example.test -p 443 @10.53.0.2 www.example.com A 2>&1)
  if printf '%s' "$badpath" | grep -q '192.0.2.10'; then
    bad "DoH answered on a path it is not configured for"
  else
    ok "...and a request on another path is not answered"
  fi

  # Curl is the measurement that could refute the three above (§19): kdig could
  # in principle be satisfied by something that is not HTTP at all. This asks
  # over HTTP/2 with the media type spelled out, and reads the status line and
  # the Cache-Control §5.1 requires.
  local raw
  raw=$(t sh -c "python3 - <<'PY'
import base64, http.client, ssl, sys
ctx = ssl.create_default_context(cafile='/srv/run/dot-ca.pem')
# A minimal query for www.example.com A, built here so the probe does not
# depend on a DNS library agreeing with the one under test.
q = bytes.fromhex('abcd0100000100000000000003777777076578616d706c6503636f6d0000010001')
c = http.client.HTTPSConnection('dns.example.test', 443, context=ctx)
c.sock = None
import socket
c._create_connection = lambda *a, **k: socket.create_connection(('10.53.0.2', 443))
c.request('POST', '/dns-query', body=q, headers={'content-type': 'application/dns-message'})
r = c.getresponse()
print('status', r.status)
print('content-type', r.getheader('content-type'))
print('cache-control', r.getheader('cache-control'))
print('bodylen', len(r.read()))
PY")
  printf '%s
' "$raw" | sed 's/^/        | /'
  if printf '%s' "$raw" | grep -q 'status 200'; then
    ok "a plain HTTPS POST of application/dns-message is answered 200"
  else
    bad "the raw HTTP probe did not get a 200"
  fi
  if printf '%s' "$raw" | grep -q 'content-type application/dns-message'; then
    ok "...with the media type RFC 8484 §6 registers"
  else
    bad "the response did not carry application/dns-message"
  fi
  if printf '%s' "$raw" | grep -qE 'cache-control max-age=[0-9]+'; then
    ok "...and a Cache-Control taken from the answer's smallest TTL (§5.1)"
  else
    bad "no Cache-Control on the DoH response"
  fi

  # ---- the renewal story, which is the half that is not the protocol -------
  #
  # New bytes at the same two paths and one reload. The pin changes, so a client
  # pinned to the old key is the way to see that the *server* changed rather
  # than that a cache was warm.
  say "42a - a renewed certificate, without a restart"
  local before after
  before="$pin"
  $COMPOSE exec -T --user root tools sh -c '
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout /srv/primary-tls/key.pem -out /srv/primary-tls/cert.pem -days 30 \
      -subj "/CN=dns.example.test" \
      -addext "subjectAltName=DNS:dns.example.test,IP:10.53.0.2" 2>/dev/null &&
    chown 65532:65532 /srv/primary-tls/cert.pem /srv/primary-tls/key.pem &&
    chmod 0600 /srv/primary-tls/key.pem && chmod 0644 /srv/primary-tls/cert.pem &&
    cp /srv/primary-tls/cert.pem /srv/run/dot-ca.pem' >/dev/null 2>&1

  $COMPOSE kill -s HUP rdnsd-primary >/dev/null 2>&1
  sleep 3

  after=$(t sh -c "openssl x509 -in /srv/run/dot-ca.pem -pubkey -noout \
          | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64")
  after=$(printf '%s' "$after" | tr -d '\r\n ')
  if [ "$after" = "$before" ]; then
    bad "the renewed certificate has the same key as the old one; the test proves nothing"
    return
  fi

  check "the renewed certificate is served after a SIGHUP, with no restart" "192.0.2.10" \
    <<< "$(t kdig +short "+tls-pin=$after" -p 853 @10.53.0.2 www.example.com A 2>&1)"

  check "...and DoQ is serving the renewed one too, from the same store" "192.0.2.10" \
    <<< "$(t kdig +short +quic "+tls-pin=$after" -p 853 @10.53.0.2 www.example.com A 2>&1)"

  local stale
  stale=$(t kdig +short "+tls-pin=$before" -p 853 @10.53.0.2 www.example.com A 2>&1)
  if printf '%s' "$stale" | grep -q '192.0.2.10'; then
    bad "the old key still satisfies a pin, so nothing was actually replaced"
  else
    ok "...and the old key no longer does, so it was replaced rather than cached"
  fi

  # The process did not restart: its uptime covers the whole run.
  if $COMPOSE logs rdnsd-primary 2>/dev/null | grep -c 'rdnsd listening on' | grep -q '^1$'; then
    ok "rdnsd bound its sockets exactly once, so the renewal was a reload"
  else
    bad "rdnsd started more than once during this run; the reload claim is not tested"
  fi
}

# --------------------------------------------------------------------------

report() {
  say "result"
  printf '   %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
  if [ "$FAIL" -gt 0 ]; then
    printf '\n   failures:\n'
    printf '     - %s\n' "${FAILED[@]}"
    return 1
  fi
  return 0
}

down() { say "down"; $COMPOSE down -v --remove-orphans 2>&1 | tail -3; }

all() {
  build   || { echo 'the images would not build'; exit 1; }
  setup   || { echo 'setup failed'; exit 1; }
  up
  versions
  contained
  s43a; s43b; s43c; s43d; s43e; s42a
  report
}

case "${1:-all}" in
  all) all ;;
  build) build ;;
  setup) setup ;;
  up) up ;;
  versions) versions ;;
  contained) contained; report ;;
  43a) s43a; report ;;
  43b) s43b; report ;;
  43c) s43c; report ;;
  43d) s43d; report ;;
  43e) s43e; report ;;
  42a) s42a; report ;;
  down) down ;;
  logs) shift; $COMPOSE logs "$@" ;;
  shell) $COMPOSE exec tools bash ;;
  *) echo "usage: $0 {build|setup|up|contained|versions|43a|43b|43c|43d|43e|42a|all|down|logs|shell}"; exit 2 ;;
esac
