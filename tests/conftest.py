"""Shared test fixtures/helpers for qwed-infra tests."""


import pytest

from qwed_infra.attestation import mint_diagnostic_attestation


def mint_token_for(guard, diagnostic, engine: str, formal_statement: str) -> str:
    """Mint a valid attestation token bound to a guard's VERIFIED diagnostic.

    The token binds qwed.query_hash == sha256(formal_statement) and
    qwed.proof_hash == diagnostic.proof_ref, which is exactly what the
    bridge's trust boundary validates before admitting (#47).
    """
    att = mint_diagnostic_attestation(diagnostic, engine=engine, query=formal_statement)
    assert att.is_issued
    return att.token


@pytest.fixture
def attestationTokenMinter():
    return mint_token_for
