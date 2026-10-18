from app.engine.checks.auth_jwt import AuthJwtCheck
from app.engine.checks.base import allows_active_probe
from app.engine.checks.bfla import BflaCheck
from app.engine.checks.bola import BolaCheck
from app.engine.checks.business_flow import BusinessFlowCheck
from app.engine.checks.data_exposure import DataExposureCheck
from app.engine.checks.fail_open import FailOpenCheck
from app.engine.checks.injection import InjectionCheck
from app.engine.checks.inventory import InventoryCheck
from app.engine.checks.mass_assignment import MassAssignmentCheck
from app.engine.checks.misconfig import MisconfigCheck
from app.engine.checks.resource_limits import ResourceLimitsCheck
from app.engine.checks.ssrf import SsrfCheck
from app.engine.checks.unsafe_consumption import UnsafeConsumptionCheck

CHECK_TYPES = {
    "bola": BolaCheck,
    "auth_jwt": AuthJwtCheck,
    "data_exposure": DataExposureCheck,
    "resource_limits": ResourceLimitsCheck,
    "bfla": BflaCheck,
    "business_flow": BusinessFlowCheck,
    "ssrf": SsrfCheck,
    "misconfig": MisconfigCheck,
    "inventory": InventoryCheck,
    "unsafe_consumption": UnsafeConsumptionCheck,
    "injection": InjectionCheck,
    "fail_open": FailOpenCheck,
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
