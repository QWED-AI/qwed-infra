__version__ = "0.3.0"

from .guards.iam_guard import IamGuard
from .guards.network_guard import NetworkGuard
from .guards.cost_guard import CostGuard
from .guards.artifact_boundary_guard import ArtifactBoundaryGuard
from .parsers.terraform_parser import TerraformParser
from .verification_context import (
    Admission,
    Decision,
    Evidence,
    Formalization,
    Interpretation,
    Proof,
    Verdict,
    VerificationContext,
    VerificationContextDocument,
    VerificationContextValidationError,
    compute_document_proof_ref,
    resolve_document_proof_ref,
    is_valid_document,
)
from .verification_context_bridge import verification_context_from_diagnostic_result
