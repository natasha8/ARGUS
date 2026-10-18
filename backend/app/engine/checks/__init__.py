from app.engine.checks.base import allows_active_probe

CHECK_TYPES = {
}


def build_checks(names: list[str]):
    selected = []
    for name in names:
        cls = CHECK_TYPES.get(name)
        if cls is not None:
            selected.append(cls())
    return selected


__all__ = ["CHECK_TYPES", "build_checks", "allows_active_probe"]
