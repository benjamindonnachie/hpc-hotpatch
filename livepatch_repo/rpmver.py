"""Small, dependency-free subset of RPM EVR comparison.

The implementation follows RPM's segmented comparison rules closely enough for
EL kernel epochs, versions and releases. It deliberately rejects empty values
at the model boundary rather than assigning ordering to malformed metadata.
"""

from __future__ import annotations

from itertools import zip_longest


def _segments(value: str) -> list[tuple[str, str]]:
    segments: list[tuple[str, str]] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "~":
            segments.append(("tilde", char))
            index += 1
            continue
        if char == "^":
            segments.append(("caret", char))
            index += 1
            continue
        if not char.isalnum():
            index += 1
            continue
        numeric = char.isdigit()
        end = index + 1
        while end < len(value):
            candidate = value[end]
            if not candidate.isalnum() or candidate.isdigit() != numeric:
                break
            end += 1
        segments.append(("num" if numeric else "alpha", value[index:end]))
        index = end
    return segments


def rpmvercmp(left: str, right: str) -> int:
    """Return -1, 0 or 1 using RPM-like segmented version ordering."""
    if left == right:
        return 0

    left_segments = _segments(left)
    right_segments = _segments(right)
    for lhs, rhs in zip_longest(left_segments, right_segments):
        if lhs is None:
            if rhs and rhs[0] == "tilde":
                return 1
            return -1
        if rhs is None:
            if lhs[0] == "tilde":
                return -1
            return 1

        left_kind, left_value = lhs
        right_kind, right_value = rhs
        if left_kind == "tilde" or right_kind == "tilde":
            if left_kind != right_kind:
                return -1 if left_kind == "tilde" else 1
            continue
        if left_kind == "caret" or right_kind == "caret":
            if left_kind != right_kind:
                return 1 if left_kind == "caret" else -1
            continue
        if left_kind != right_kind:
            return 1 if left_kind == "num" else -1
        if left_kind == "num":
            lhs_number = left_value.lstrip("0") or "0"
            rhs_number = right_value.lstrip("0") or "0"
            if len(lhs_number) != len(rhs_number):
                return 1 if len(lhs_number) > len(rhs_number) else -1
            if lhs_number != rhs_number:
                return 1 if lhs_number > rhs_number else -1
        elif left_value != right_value:
            return 1 if left_value > right_value else -1
    return 0


def evr_cmp(
    left_epoch: str,
    left_version: str,
    left_release: str,
    right_epoch: str,
    right_version: str,
    right_release: str,
) -> int:
    """Compare two epoch-version-release tuples."""
    left_epoch_number = int(left_epoch or "0")
    right_epoch_number = int(right_epoch or "0")
    if left_epoch_number != right_epoch_number:
        return 1 if left_epoch_number > right_epoch_number else -1
    version_result = rpmvercmp(left_version, right_version)
    if version_result:
        return version_result
    return rpmvercmp(left_release, right_release)
