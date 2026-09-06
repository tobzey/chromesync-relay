#!/bin/sh
# CI-only network isolation. Production locks keep their legacy 20000..59999
# mapping; automatic listener/client ports must not collide with that range.
# No reserved-port policy or production machine setting is modified.
set -eu

if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
  printf '%s\n' 'Network isolation is only for temporary GitHub-hosted CI runners.' >&2
  exit 1
fi

network_fail() {
  printf '%s\n' 'CI ephemeral port range could not be verified as 60000..65535.' >&2
  exit 1
}

case "$(uname -s)" in
  Linux)
    # Leave net.ipv4.ip_local_reserved_ports unchanged: replacing it would erase
    # independent reservations. The new allocation range excludes our locks.
    sudo -n sysctl -w 'net.ipv4.ip_local_port_range=60000 65535'
    network_actual=$(sysctl -n net.ipv4.ip_local_port_range)
    read -r network_first network_last network_extra <<EOF
$network_actual
EOF
    [ "$network_first" = 60000 ] && [ "$network_last" = 65535 ] && [ -z "$network_extra" ] || network_fail
    ;;
  Darwin)
    sudo -n sysctl -w \
      net.inet.ip.portrange.last=65535 \
      net.inet.ip.portrange.first=60000 \
      net.inet.ip.portrange.hilast=65535 \
      net.inet.ip.portrange.hifirst=60000
    for network_key in first hifirst; do
      [ "$(sysctl -n "net.inet.ip.portrange.$network_key")" = 60000 ] || network_fail
    done
    for network_key in last hilast; do
      [ "$(sysctl -n "net.inet.ip.portrange.$network_key")" = 65535 ] || network_fail
    done
    ;;
  *) network_fail ;;
esac

printf '%s\n' 'CI automatic ports: 60000..65535; ChromeSync lock ports remain unchanged.'
