"""
Checks for Docker-related privilege escalation vectors:
  - current user in the 'docker' group (effectively root-equivalent)
  - world-writable Docker socket
"""

import grp
import os
import pwd

from core.finding import Finding, Severity

NAME = "Docker"

DOCKER_SOCKET = "/var/run/docker.sock"


def _current_user_in_docker_group() -> bool:
    try:
        current_user = pwd.getpwuid(os.getuid())
        docker_group = grp.getgrnam("docker")
        # Group membership may come from the user's primary or supplementary
        # group IDs, even when the username is absent from gr_mem.
        active_gids = set(os.getgroups()) | {current_user.pw_gid}
        return current_user.pw_name in docker_group.gr_mem or docker_group.gr_gid in active_gids
    except KeyError:
        return False


def run() -> list[Finding]:
    findings = []
    counter = 1

    if _current_user_in_docker_group():
        findings.append(
            Finding(
                id=f"DOCKER-{counter:03d}",
                title="Current user is a member of the 'docker' group",
                severity=Severity.HIGH,
                category=NAME,
                evidence="User found in group membership: docker",
                impact=(
                    "Membership in the docker group is effectively "
                    "equivalent to root access on the host: a user can "
                    "mount the host filesystem into a container "
                    "(e.g. docker run -v /:/mnt) and read/write files as "
                    "root."
                ),
                remediation=(
                    "Only add trusted, effectively-root-equivalent users "
                    "to the docker group. Consider rootless Docker for "
                    "less-trusted users."
                ),
                affected_path="docker group membership",
            )
        )
        counter += 1

    if os.path.exists(DOCKER_SOCKET):
        try:
            mode = oct(os.stat(DOCKER_SOCKET).st_mode)
        except OSError:
            mode = "unknown"

        if os.access(DOCKER_SOCKET, os.W_OK):
            findings.append(
                Finding(
                    id=f"DOCKER-{counter:03d}",
                    title="Docker socket is writable by current user",
                    severity=Severity.CRITICAL,
                    category=NAME,
                    evidence=f"Path: {DOCKER_SOCKET}\nPermissions: {mode}",
                    impact=(
                        "Write access to the Docker socket allows full "
                        "control of the Docker daemon, which runs as root. "
                        "This can be used to start a privileged container "
                        "mounting the host filesystem, resulting in full "
                        "host compromise."
                    ),
                    remediation=(
                        "Restrict access to the Docker socket to trusted "
                        "administrators only."
                    ),
                    affected_path=DOCKER_SOCKET,
                )
            )
    return findings
