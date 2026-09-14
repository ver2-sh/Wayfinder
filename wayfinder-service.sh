#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WAYFINDER_DIR="${NORTED_REPOS_DIR:-/srv/norted/repos}/project-wayfinder"
UNIT_NAME="wayfinder.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
GLOBAL_LINK="/usr/local/bin/wayfinder"
BINARY="${WAYFINDER_DIR}/target/release/wayfinder"

if (( EUID == 0 )) && [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  echo "Run this script as your normal user, not with sudo." >&2
  exit 1
fi

if (( EUID == 0 )); then
  SUDO=()
else
  command -v sudo >/dev/null 2>&1 || {
    echo "sudo is required when not running as root." >&2
    exit 1
  }
  SUDO=(sudo)
fi

usage() {
  cat <<EOF
Usage: wayfinder <command>

Manage the Wayfinder daemon (Rust) as a systemd service.
Also callable as ./wayfinder-service.sh <command>.

Commands:
  install   Build Wayfinder, install the systemd unit, install the
            global 'wayfinder' command, and start the service
  update    Git-pull (ff-only), rebuild, and restart the service
  build     Build the release binary with cargo
  start     Start the service
  stop      Stop the service
  restart   Restart the service
  status    Show service status
  logs      Follow service logs
  disable   Stop and disable the service
  remove    Stop, disable, remove the systemd unit and global command

Environment:
  NORTED_REPOS_DIR    Repository root (default: /srv/norted/repos)
  WAYFINDER_DATA_DIR  Explicit Wayfinder private data directory passed to the
                      service as --data-dir (default: the service account's
                      OS application-data directory, e.g. ~/.local/share/wayfinder)

The daemon must be initialized before the service can run:
  wayfinder init --name NAME   (as the service account, or with --data-dir)
EOF
}

require_wayfinder() {
  [[ -d "$WAYFINDER_DIR" && -f "$WAYFINDER_DIR/Cargo.toml" ]] || {
    echo "Wayfinder repository not found at ${WAYFINDER_DIR}." >&2
    echo "Clone it there, or set NORTED_REPOS_DIR." >&2
    exit 1
  }
}

require_cargo() {
  command -v cargo >/dev/null 2>&1 || {
    echo "cargo is not installed; install Rust via rustup." >&2
    exit 1
  }
}

build_wayfinder() {
  require_wayfinder
  require_cargo
  echo "Building Wayfinder (release)..."
  (cd "$WAYFINDER_DIR" && cargo build --release -p wayfinder)
  echo "Build complete: ${BINARY}"
}

update_wayfinder() {
  require_wayfinder
  require_cargo

  echo "Fetching latest changes for project-wayfinder..."
  git -C "$WAYFINDER_DIR" fetch --prune origin

  local head_sha upstream_sha upstream
  head_sha="$(git -C "$WAYFINDER_DIR" rev-parse HEAD)"
  upstream="$(git -C "$WAYFINDER_DIR" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
  if [[ -z "$upstream" || "$upstream" != origin/* ]]; then
    echo "Current branch has no upstream tracking origin; skipping update." >&2
    exit 1
  fi
  upstream_sha="$(git -C "$WAYFINDER_DIR" rev-parse "$upstream")"

  if [[ "$head_sha" == "$upstream_sha" ]]; then
    echo "Already up to date at ${head_sha:0:12}."
    return 0
  fi

  local dirty
  if ! dirty="$(git -C "$WAYFINDER_DIR" status --porcelain 2>/dev/null)"; then
    echo "Cannot inspect the worktree; skipping update." >&2
    exit 1
  fi
  if [[ -n "$dirty" ]]; then
    echo "Worktree is dirty or has untracked files; refusing to update." >&2
    echo "Commit or stash your changes, then rerun 'wayfinder update'." >&2
    exit 1
  fi

  if git -C "$WAYFINDER_DIR" merge-base --is-ancestor HEAD "$upstream"; then
    echo "Fast-forwarding to ${upstream_sha:0:12}..."
    git -C "$WAYFINDER_DIR" merge --ff-only "$upstream"
  elif git -C "$WAYFINDER_DIR" merge-base --is-ancestor "$upstream" HEAD; then
    echo "Local is ahead of ${upstream}; leaving it unchanged." >&2
    return 0
  else
    echo "Local branch has diverged from ${upstream}; refusing to update." >&2
    echo "Rebase or merge manually, then rerun 'wayfinder update'." >&2
    exit 1
  fi

  echo
  build_wayfinder
  echo
  "${SUDO[@]}" systemctl restart "$UNIT_NAME"
  "${SUDO[@]}" systemctl is-active --quiet "$UNIT_NAME"
  echo "Wayfinder updated and restarted."
}

install_unit() {
  build_wayfinder

  local run_user run_group home_dir tmp_unit backup_unit
  local old_unit_exists=0 old_active=0 old_enabled=0 rollback_needed=0

  run_user="$(stat -c '%U' "$WAYFINDER_DIR")"
  run_group="$(stat -c '%G' "$WAYFINDER_DIR")"
  home_dir="$(getent passwd "$run_user" | cut -d: -f6)"
  [[ -n "$home_dir" ]] || {
    echo "Could not determine home directory for ${run_user}." >&2
    exit 1
  }

  local data_dir exec_start
  data_dir="${WAYFINDER_DATA_DIR:-${home_dir}/.local/share/wayfinder}"
  if [[ -n "${WAYFINDER_DATA_DIR:-}" ]]; then
    exec_start="${BINARY} --data-dir ${WAYFINDER_DATA_DIR} daemon"
  else
    exec_start="${BINARY} daemon"
  fi
  if [[ ! -f "${data_dir}/config.json" ]]; then
    echo "WARNING: no Wayfinder configuration at ${data_dir}." >&2
    echo "The service will fail until it is initialized, e.g.:" >&2
    echo "  sudo -u ${run_user} ${exec_start/daemon/init --name NAME}" >&2
  fi

  tmp_unit="$(mktemp)"
  backup_unit="$(mktemp)"
  trap 'rm -f "$tmp_unit" "$backup_unit"' RETURN

  cat > "$tmp_unit" <<EOF
[Unit]
Description=Wayfinder daemon (private network of MCP shell execution nodes)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${run_user}
Group=${run_group}
WorkingDirectory=${WAYFINDER_DIR}
Environment=HOME=${home_dir}
ExecStart=${exec_start}
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

  if "${SUDO[@]}" test -e "$UNIT_PATH"; then
    old_unit_exists=1
    "${SUDO[@]}" cat "$UNIT_PATH" > "$backup_unit"
  fi
  if systemctl is-active --quiet "$UNIT_NAME" 2>/dev/null; then
    old_active=1
  fi
  if systemctl is-enabled --quiet "$UNIT_NAME" 2>/dev/null; then
    old_enabled=1
  fi

  rollback_unit() {
    local original_rc="${1:-1}"
    trap - ERR
    set +e

    echo
    echo "Service activation failed; restoring the previous systemd state..." >&2

    if (( old_unit_exists )); then
      "${SUDO[@]}" install -m 0644 "$backup_unit" "$UNIT_PATH"
    else
      "${SUDO[@]}" rm -f "$UNIT_PATH"
    fi
    "${SUDO[@]}" systemctl daemon-reload

    if (( old_enabled )); then
      "${SUDO[@]}" systemctl enable "$UNIT_NAME" >/dev/null 2>&1
    else
      "${SUDO[@]}" systemctl disable "$UNIT_NAME" >/dev/null 2>&1
    fi

    if (( old_active )); then
      "${SUDO[@]}" systemctl restart "$UNIT_NAME"
      if ! systemctl is-active --quiet "$UNIT_NAME"; then
        echo "WARNING: previous service could not be restored to active state automatically." >&2
      fi
    else
      "${SUDO[@]}" systemctl stop "$UNIT_NAME" >/dev/null 2>&1
    fi

    set -e
    exit "$original_rc"
  }

  on_error() {
    local rc=$?
    if (( rollback_needed )); then
      rollback_unit "$rc"
    fi
    exit "$rc"
  }

  trap on_error ERR

  echo "Installing systemd unit..."
  rollback_needed=1
  "${SUDO[@]}" install -m 0644 "$tmp_unit" "$UNIT_PATH"
  "${SUDO[@]}" systemctl daemon-reload
  "${SUDO[@]}" systemctl enable "$UNIT_NAME"

  if (( old_active )); then
    "${SUDO[@]}" systemctl restart "$UNIT_NAME"
  else
    "${SUDO[@]}" systemctl start "$UNIT_NAME"
  fi

  "${SUDO[@]}" systemctl is-active --quiet "$UNIT_NAME"

  rollback_needed=0
  trap - ERR

  # Install the global 'wayfinder' symlink so the script is callable from anywhere.
  if [[ -e "$GLOBAL_LINK" && ! -L "$GLOBAL_LINK" ]]; then
    echo "WARNING: ${GLOBAL_LINK} exists but is not a symlink; leaving it unchanged." >&2
  else
    local tmp_link="${ROOT}/.wayfinder.new.$$"
    rm -f "$tmp_link"
    ln -s "${ROOT}/wayfinder-service.sh" "$tmp_link"
    "${SUDO[@]}" mv -Tf "$tmp_link" "$GLOBAL_LINK"
  fi

  echo
  "${SUDO[@]}" systemctl --no-pager --full status "$UNIT_NAME"
}

cmd="${1:-}"
case "$cmd" in
  install)
    install_unit
    ;;
  update)
    update_wayfinder
    ;;
  build)
    build_wayfinder
    ;;
  start)
    require_wayfinder
    "${SUDO[@]}" systemctl start "$UNIT_NAME"
    ;;
  stop)
    "${SUDO[@]}" systemctl stop "$UNIT_NAME"
    ;;
  restart)
    require_wayfinder
    "${SUDO[@]}" systemctl restart "$UNIT_NAME"
    "${SUDO[@]}" systemctl is-active --quiet "$UNIT_NAME"
    ;;
  status)
    "${SUDO[@]}" systemctl --no-pager --full status "$UNIT_NAME"
    ;;
  logs)
    "${SUDO[@]}" journalctl -u "$UNIT_NAME" -n 100 -f
    ;;
  disable)
    "${SUDO[@]}" systemctl disable --now "$UNIT_NAME"
    ;;
  remove)
    "${SUDO[@]}" systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
    "${SUDO[@]}" rm -f "$UNIT_PATH"
    "${SUDO[@]}" systemctl daemon-reload
    # Remove the global symlink only if it points at this script.
    if [[ -L "$GLOBAL_LINK" ]]; then
      local resolved
      resolved="$(readlink -f "$GLOBAL_LINK" 2>/dev/null || true)"
      if [[ "$resolved" == "${ROOT}/wayfinder-service.sh" ]]; then
        "${SUDO[@]}" rm -f "$GLOBAL_LINK"
      fi
    fi
    echo "Removed ${UNIT_PATH}. Wayfinder source was left untouched."
    ;;
  -h|--help|"")
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
