from app.engine.checks.auth_jwt import AuthJwtCheck
from app.engine.checks.base import allows_active_probe
from app.engine.checks.bfla import BflaCheck
from app.engine.checks.bola import BolaCheck
from app.engine.checks.data_exposure import DataExposureCheck
from app.engine.checks.injection import InjectionCheck
from app.engine.checks.mass_assignment import MassAssignmentCheck
from app.engine.checks.ssrf import SsrfCheck

CHECK_TYPES = {
    "bola": BolaCheck,
    "auth_jwt": AuthJwtCheck,
    "data_exposure": DataExposureCheck,
    "bfla": BflaCheck,
    "ssrf": SsrfCheck,
    "injection": InjectionCheck,
    "mass_assignment": MassAssignmentCheck,
}


def build_checks(names: list[str]):
    selected = []
    for name in names:
        cls = CHECK_TYPES.get(name)
        if cls is not None:
            selected.append(cls())
    return selected


__all__ = ["CHECK_TYPES", "build_checks", "allows_active_probe"]
