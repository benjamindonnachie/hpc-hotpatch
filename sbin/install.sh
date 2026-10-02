#!/usr/bin/env bash
# Install the central livepatch repository builder and timer.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_PREFIX=""
DRY_RUN=0
ENABLE_TIMER=0
PROFILE="el9_8-x86_64"
WORK_ROOT=""
STATE_DIR=""
REPOSITORY_ROOT=""
BUILD_USER="klp-build"
BUILD_GROUP="klp-build"

usage() {
    cat <<'EOF'
Usage: install.sh [--dry-run] [--root PATH] [--profile NAME]
                   [--work-root PATH] [--state-dir PATH] [--repository-root PATH]
                   [--build-user NAME] [--build-group NAME]
                   [--enable|--no-enable]

  --dry-run          Print operations without changing the filesystem.
  --root PATH        Install beneath PATH for packaging/tests; implies --no-enable.
  --profile          Install/configure this systemd profile instance.
  --work-root PATH   Kernel source trees, ccache, per-job build workspaces.
                      Default: /var/lib/klp-policy/build/<profile>
  --state-dir PATH   Registry/plan/escalation state (small, durable).
                      Default: /var/lib/livepatch-repo/<profile>/state
  --repository-root PATH
                      Published RPM repository, shared across profiles.
                      Default: /srv/klp/repo
  --build-user NAME  System account the timer runs as. Created if missing,
                      no login shell, no sudo rights. Default: klp-build
  --build-group NAME Primary group for --build-user. Default: klp-build
  --enable           Validate configuration, then enable and start the timer.
  --no-enable        Install units but do not enable or start the timer.
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
        --work-root)
            shift
            [[ $# -gt 0 && "$1" == /* ]] \
                || { echo "install.sh: --work-root requires an absolute path" >&2; exit 2; }
            WORK_ROOT="${1%/}"
            ;;
        --state-dir)
            shift
            [[ $# -gt 0 && "$1" == /* ]] \
                || { echo "install.sh: --state-dir requires an absolute path" >&2; exit 2; }
            STATE_DIR="${1%/}"
            ;;
        --repository-root)
            shift
            [[ $# -gt 0 && "$1" == /* ]] \
                || { echo "install.sh: --repository-root requires an absolute path" >&2; exit 2; }
            REPOSITORY_ROOT="${1%/}"
            ;;
        --build-user)
            shift
            [[ $# -gt 0 && "$1" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] \
                || { echo "install.sh: --build-user requires a safe account name" >&2; exit 2; }
            BUILD_USER="$1"
            ;;
        --build-group)
            shift
            [[ $# -gt 0 && "$1" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] \
                || { echo "install.sh: --build-group requires a safe group name" >&2; exit 2; }
            BUILD_GROUP="$1"
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

# Large, disposable build workspace and the small, durable state/registry
# both default to dedicated storage outside the root filesystem; the
# published repository is shared across profiles. All three are overridable
# per deployment with --work-root/--state-dir/--repository-root.
[[ -n "${WORK_ROOT}" ]] || WORK_ROOT="$(target /var/lib/klp-policy/build)/${PROFILE}"
[[ -n "${STATE_DIR}" ]] || STATE_DIR="$(target /var/lib/livepatch-repo)/${PROFILE}/state"
[[ -n "${REPOSITORY_ROOT}" ]] || REPOSITORY_ROOT="$(target /srv/klp)/repo"

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
elif [[ "${DRY_RUN}" == "1" ]]; then
    log "[DRY-RUN] would render ${environment}" \
        "REPOSITORY_ROOT=${REPOSITORY_ROOT} WORK_ROOT=${WORK_ROOT} STATE_DIR=${STATE_DIR}"
else
    {
        printf '# Rendered by install.sh on %s for profile %s.\n' \
            "$(date -u +%FT%TZ)" "${PROFILE}"
        printf '# Profiles for successive minor streams of one EL major/architecture\n'
        printf '# may share REPOSITORY_ROOT; publication.lock serialises publication.\n'
        printf 'REPOSITORY_ROOT=%s\n' "${REPOSITORY_ROOT}"
        printf 'WORK_ROOT=%s\n' "${WORK_ROOT}"
        printf 'STATE_DIR=%s\n' "${STATE_DIR}"
    } | install -D -m 0640 /dev/stdin "${environment}"
fi

run install -d -m 0755 "${unit_dir}"
for unit in livepatch-repo-refresh@.service livepatch-repo-refresh@.timer; do
    if [[ "${unit}" == *.service ]]; then
        if [[ "${DRY_RUN}" == "1" ]]; then
            log "[DRY-RUN] would install ${unit_dir}/${unit} with User=${BUILD_USER} Group=${BUILD_GROUP}"
        else
            sed \
                -e "s/^User=.*/User=${BUILD_USER}/" \
                -e "s/^Group=.*/Group=${BUILD_GROUP}/" \
                "${REPO_ROOT}/systemd/${unit}" \
                | install -D -m 0644 /dev/stdin "${unit_dir}/${unit}"
        fi
    else
        run install -m 0644 \
            "${REPO_ROOT}/systemd/${unit}" \
            "${unit_dir}/${unit}"
    fi
done

run install -d -m 0750 "${STATE_DIR}"
run install -d -m 0750 "${WORK_ROOT}"
run install -d -m 0755 "${REPOSITORY_ROOT}"

if [[ -z "${ROOT_PREFIX}" ]]; then
    if ! getent group "${BUILD_GROUP}" >/dev/null 2>&1; then
        run groupadd --system "${BUILD_GROUP}"
    fi
    if ! getent passwd "${BUILD_USER}" >/dev/null 2>&1; then
        run useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid "${BUILD_GROUP}" \
            --comment "livepatch-repo build account (minimal rights, no sudo)" \
            "${BUILD_USER}"
    fi
    # The build account needs no elevated rights: /boot/config-* and the
    # debuginfo vmlinux are world-readable, and rpmbuild/kpatch-build/gcc/
    # createrepo_c only ever touch its own directories below.
    run chown -R "${BUILD_USER}:${BUILD_GROUP}" "${STATE_DIR}" "${WORK_ROOT}" "${REPOSITORY_ROOT}"
    # Config/env stay root-owned (the build account cannot modify its own
    # configuration, even if compromised) but must be group-readable so the
    # service, running as BUILD_USER, can actually load them.
    run chgrp "${BUILD_GROUP}" "${configuration}" "${environment}"
fi

if [[ -z "${ROOT_PREFIX}" && "${ENABLE_TIMER}" == "1" ]]; then
    if [[ "${DRY_RUN}" != "1" ]]; then
        env PYTHONPATH="${application}" python3 -c '
from pathlib import Path
import sys
from livepatch_repo.config import load_config

config = load_config(Path(sys.argv[1]))
if config.rpm_sign_command_template and not config.rpm_verify_command_template:
    raise SystemExit(
        "an automatic signing command is configured without a verification command"
    )
if config.require_rpm_signing and not config.rpm_verify_command_template:
    raise SystemExit(
        "signing is required but no verification command is configured"
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

log "installation complete (work-root=${WORK_ROOT} state-dir=${STATE_DIR} repository-root=${REPOSITORY_ROOT} build-user=${BUILD_USER})"
