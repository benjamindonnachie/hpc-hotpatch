#!/usr/bin/env bash
# Install the central livepatch repository builder and timer.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_PREFIX=""
DRY_RUN=0
ENABLE_TIMER=0
PROFILE="el9_8-x86_64"

usage() {
    cat <<'EOF'
Usage: install.sh [--dry-run] [--root PATH] [--profile NAME] [--enable|--no-enable]

  --dry-run    Print operations without changing the filesystem.
  --root PATH  Install beneath PATH for packaging/tests; implies --no-enable.
  --profile    Install/configure this systemd profile instance.
  --enable     Validate configuration, then enable and start the timer.
  --no-enable  Install units but do not enable or start the timer.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            ;;
        --root)
            shift
            [[ $# -gt 0 && "$1" == /* ]] \
                || { echo "install.sh: --root requires an absolute path" >&2; exit 2; }
            ROOT_PREFIX="${1%/}"
            ENABLE_TIMER=0
            ;;
        --enable)
            ENABLE_TIMER=1
            ;;
        --profile)
            shift
            [[ $# -gt 0 && "$1" =~ ^[A-Za-z0-9_.-]+$ ]] \
                || { echo "install.sh: --profile requires a safe name" >&2; exit 2; }
            PROFILE="$1"
            ;;
        --no-enable)
            ENABLE_TIMER=0
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "install.sh: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

log() { echo "install.sh: $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

run() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        printf 'install.sh: [DRY-RUN]'
        printf ' %q' "$@"
        printf '\n'
    else
        "$@"
    fi
}

target() {
    printf '%s%s\n' "${ROOT_PREFIX}" "$1"
}

if [[ -z "${ROOT_PREFIX}" && "${DRY_RUN}" != "1" && "${EUID}" -ne 0 ]]; then
    die "a real installation must run as root"
fi

for source in \
    "${REPO_ROOT}/etc/livepatch-repo.conf.example" \
    "${REPO_ROOT}/etc/livepatch-repo.env.example" \
    "${REPO_ROOT}/systemd/livepatch-repo-refresh@.service" \
    "${REPO_ROOT}/systemd/livepatch-repo-refresh@.timer"; do
    [[ -f "${source}" ]] || die "required source file is missing: ${source}"
done
[[ -f "${REPO_ROOT}/livepatch_repo/__main__.py" ]] \
    || die "livepatch_repo package is incomplete"

log "checking runtime commands"
for command in \
    python3 dnf rpmbuild rpmspec rpm rpmkeys rpmsign createrepo_c \
    git patch modinfo; do
    if command -v "${command}" >/dev/null 2>&1; then
        log "OK: ${command}"
    else
        log "WARN: missing ${command}"
    fi
done
if command -v kpatch-build >/dev/null 2>&1; then
    log "OK: kpatch-build"
elif command -v klp-build >/dev/null 2>&1; then
    log "OK: klp-build"
else
    log "WARN: no livepatch builder found"
fi

application="$(target /opt/livepatch-repo)"
configuration_dir="$(target /etc/livepatch-repo)"
configuration="${configuration_dir}/${PROFILE}.conf"
environment="${configuration_dir}/${PROFILE}.env"
unit_dir="$(target /etc/systemd/system)"
state_root="$(target /var/lib/livepatch-repo)"
repository_root="$(target /srv/livepatch-repo)"

run install -d -m 0755 "${application}/livepatch_repo"
for source in "${REPO_ROOT}"/livepatch_repo/*.py; do
    run install -m 0644 "${source}" "${application}/livepatch_repo/"
done

run install -d -m 0755 "${configuration_dir}"
if [[ -e "${configuration}" ]]; then
    log "preserving existing ${configuration}"
else
    run install -m 0640 \
        "${REPO_ROOT}/etc/livepatch-repo.conf.example" \
        "${configuration}"
    log "installed ${configuration}; configure the signing key before enabling"
fi
if [[ -e "${environment}" ]]; then
    log "preserving existing ${environment}"
else
    run install -m 0640 \
        "${REPO_ROOT}/etc/livepatch-repo.env.example" \
        "${environment}"
fi

run install -d -m 0755 "${unit_dir}"
for unit in livepatch-repo-refresh@.service livepatch-repo-refresh@.timer; do
    run install -m 0644 \
        "${REPO_ROOT}/systemd/${unit}" \
        "${unit_dir}/${unit}"
done

run install -d -m 0700 \
    "${state_root}/${PROFILE}/state" \
    "${state_root}/${PROFILE}/jobs"
run install -d -m 0755 "${repository_root}/alma/9/x86_64"

if [[ -z "${ROOT_PREFIX}" && "${ENABLE_TIMER}" == "1" ]]; then
    if [[ "${DRY_RUN}" != "1" ]]; then
        env PYTHONPATH="${application}" python3 -c '
from pathlib import Path
import sys
from livepatch_repo.config import load_config

config = load_config(Path(sys.argv[1]))
if config.require_rpm_signing and (
    not config.rpm_sign_command_template
    or not config.rpm_verify_command_template
):
    raise SystemExit(
        "signing is required but its signing or verification command is empty"
    )
' "${configuration}" \
            || die "configuration is not ready for timer enablement"
    fi
    run systemctl daemon-reload
    run systemctl enable --now "livepatch-repo-refresh@${PROFILE}.timer"
    log "timer enabled; inspect with systemctl status livepatch-repo-refresh@${PROFILE}.timer"
else
    log "timer was not enabled"
fi

log "installation complete"
