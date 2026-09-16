#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
command_name="${1:-help}"
case "$command_name" in
  build) exec "$repo_dir/build-production.sh" ;;
  install)
    # Run as the account whose OS privileges remote commands should receive.
    run_user="$(id -un)"
    run_group="$(id -gn)"
    data_dir="${WAYFINDER_DATA_DIR:-$HOME/.local/share/wayfinder}"
    [[ "$data_dir" == /* && "$data_dir" != *[[:space:]\%\"\\]* ]] || { echo 'Use an absolute data directory without whitespace, %, quote or backslash' >&2; exit 1; }
    if (( EUID == 0 )); then elevate=(); else elevate=(sudo); fi
    "$repo_dir/build-production.sh"
    tmp_unit="$(mktemp)"
    trap 'rm -f "$tmp_unit"' EXIT
    cat > "$tmp_unit" <<UNIT
[Unit]
Description=Wayfinder Sync Chain agent
After=network-online.target
Wants=network-online.target
ConditionPathExists=$data_dir/installation.json

[Service]
Type=simple
User=$run_user
Group=$run_group
ExecStart=/usr/local/bin/wayfinder --data-dir $data_dir daemon
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
    "${elevate[@]}" install -m 0755 "$repo_dir/target/release/wayfinder" /usr/local/bin/wayfinder.new
    "${elevate[@]}" mv -Tf /usr/local/bin/wayfinder.new /usr/local/bin/wayfinder
    "${elevate[@]}" install -m 0644 "$tmp_unit" /etc/systemd/system/wayfinder.service
    "${elevate[@]}" systemctl daemon-reload
    "${elevate[@]}" systemctl enable wayfinder.service
    "${elevate[@]}" systemctl restart wayfinder.service
    echo "Agent installed as $run_user. Commands execute with that account's OS privileges."
    echo "If not enrolled, run: wayfinder --data-dir $data_dir chain create --name DEVICE"
    echo 'Then run: sudo systemctl start wayfinder.service'
    ;;
  start|stop|restart|status) exec systemctl "$command_name" wayfinder.service ;;
  logs) exec journalctl -u wayfinder.service -f ;;
  *) echo 'Usage: ./wayfinder-service.sh install|build|start|stop|restart|status|logs'
     echo 'The installed wayfinder command is the agent CLI. This script installs no gateway.' ;;
esac
