"""Native verification module for Phase 3 runtime security."""

from .eligibility import NativeEligibilityDecision, evaluate_native
from .executor import (
    AREA_HARD_MAXIMUMS,
    DEFAULT_REQUEST_TIMEOUT,
    FIXTURE_MAX_REQUESTS,
    LOCAL_APP_MAX_REQUESTS,
    MAX_AREA_TIMEOUT,
    MAX_TOTAL_TIMEOUT,
    SETUP_MAX_REQUESTS,
    VERIFICATION_AREAS,
    AreaExecutionResult,
    NativeExecutionResult,
    NativeExecutor,
    PlannedRequest,
    RequestExecutionResult,
    execute_native_plan,
)
from .identity import IdentityVault, SecretValue, SessionState
from .plan import AreaPlan, NativePlan, build_plan
from .setup_adapter import (
    SETUP_EXPIRES_IN_SECONDS,
    SETUP_SCHEMA,
    IdentitySetupResult,
    build_setup_payload,
    build_setup_request,
    validate_setup_response,
)

__all__ = [
    "AREA_HARD_MAXIMUMS",
    "DEFAULT_REQUEST_TIMEOUT",
    "FIXTURE_MAX_REQUESTS",
    "LOCAL_APP_MAX_REQUESTS",
    "MAX_AREA_TIMEOUT",
    "MAX_TOTAL_TIMEOUT",
    "SETUP_EXPIRES_IN_SECONDS",
    "SETUP_MAX_REQUESTS",
    "SETUP_SCHEMA",
    "VERIFICATION_AREAS",
    "AreaExecutionResult",
    "AreaPlan",
    "IdentitySetupResult",
    "IdentityVault",
    "NativeEligibilityDecision",
    "NativeExecutionResult",
    "NativeExecutor",
    "NativePlan",
    "PlannedRequest",
    "RequestExecutionResult",
    "SecretValue",
    "SessionState",
    "build_plan",
    "build_setup_payload",
    "build_setup_request",
    "evaluate_native",
    "execute_native_plan",
    "validate_setup_response",
]
