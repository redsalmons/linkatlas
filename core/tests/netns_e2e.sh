#!/usr/bin/env bash
# End-to-end test on Linux (needs sudo): a client in a network namespace whose default
# route is the TUN device; the harness relays its traffic through the tunnel.
set -euo pipefail
HARNESS=${1:?usage: netns_e2e.sh <path/to/tun_harness>}
NS=wdtest; DEV=wdtun0; PORT=18080
HOSTIP=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
WORK=$(mktemp -d)
cleanup() { sudo ip netns del $NS 2>/dev/null || true; kill ${HTTP:-} 2>/dev/null || true; sudo kill ${HPID:-} 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

head -c 20000000 /dev/urandom > "$WORK/blob.bin"
(cd "$WORK" && exec python3 -m http.server $PORT --bind "$HOSTIP" >/dev/null 2>&1) & HTTP=$!
sudo ip netns add $NS
sudo "$HARNESS" $DEV 40 > "$WORK/harness.log" 2>&1 & HPID=$!
for _ in $(seq 50); do ip link show $DEV >/dev/null 2>&1 && break; sleep 0.1; done
sudo ip link set $DEV netns $NS
sudo ip netns exec $NS ip link set lo up
sudo ip netns exec $NS ip addr add 10.8.0.2/24 dev $DEV
sudo ip netns exec $NS ip link set $DEV up
sudo ip netns exec $NS ip route add default dev $DEV
sleep 1
fail=0
want=$(sha256sum < "$WORK/blob.bin")
got=$(sudo ip netns exec $NS curl -s --max-time 30 "http://$HOSTIP:$PORT/blob.bin" | sha256sum)
[ "$want" = "$got" ] && echo "PASS tcp 20MB download intact" || { echo "FAIL tcp download"; fail=1; }
head -c 3000000 /dev/urandom > "$WORK/up.bin"
code=$(sudo ip netns exec $NS curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST --data-binary @"$WORK/up.bin" "http://$HOSTIP:$PORT/" || true)
[ -n "$code" ] && [ "$code" != "000" ] && echo "PASS tcp 3MB upload (http $code)" || { echo "FAIL tcp upload"; fail=1; }
ip=$(sudo ip netns exec $NS dig +short +time=3 +tries=2 @1.1.1.1 example.com A | grep -E '^[0-9.]+$' | head -1 || true)
[ -n "$ip" ] && echo "PASS udp dns via 1.1.1.1 -> $ip" || { echo "FAIL udp dns"; fail=1; }
if [ -n "$ip" ]; then
  code=$(sudo ip netns exec $NS curl -s -o /dev/null -w '%{http_code}' --max-time 15 --resolve example.com:443:$ip https://example.com/ || true)
  [ "$code" = "200" ] && echo "PASS https to internet (200)" || { echo "FAIL https ($code)"; fail=1; }
fi
sudo pkill -INT -f "^$HARNESS $DEV" || true
for _ in $(seq 50); do grep -q "^hook" "$WORK/harness.log" && break; sleep 0.1; done
cat "$WORK/harness.log"
exit $fail
