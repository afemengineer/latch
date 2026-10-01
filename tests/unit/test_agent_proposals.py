import json

import pytest

from latch.agent.proposals import (
    FinishProposal,
    ProposalParseError,
    ReadProposal,
    parse_proposal,
)


def test_parse_read_proposal() -> None:
    proposal = parse_proposal(
        json.dumps(
            {
                "action": "filesystem.read",
                "arguments": {"path": "/tmp/invoice.txt"},
            }
        )
    )

    assert proposal == ReadProposal("/tmp/invoice.txt")


def test_parse_finish_proposal() -> None:
    proposal = parse_proposal(
        json.dumps(
            {
                "action": "finish",
                "arguments": {"message": "Done"},
            }
        )
    )

    assert proposal == FinishProposal("Done")


def test_authority_bearing_extra_fields_are_rejected() -> None:
    with pytest.raises(ProposalParseError, match=r"extra=.*grant_id"):
        parse_proposal(
            json.dumps(
                {
                    "action": "filesystem.read",
                    "arguments": {
                        "path": "/tmp/invoice.txt",
                        "grant_id": "grant_model_minted",
                    },
                }
            )
        )


def test_top_level_extra_fields_are_rejected() -> None:
    with pytest.raises(ProposalParseError, match=r"extra=.*permission"):
        parse_proposal(
            json.dumps(
                {
                    "action": "finish",
                    "arguments": {"message": "Done"},
                    "permission": "allow_everything",
                }
            )
        )


@pytest.mark.parametrize(
    "text",
    [
        "not-json",
        "[]",
        '{"action":"filesystem.read"}',
        '{"action":"shell","arguments":{}}',
    ],
)
def test_malformed_or_unsupported_proposals_are_rejected(text: str) -> None:
    with pytest.raises(ProposalParseError):
        parse_proposal(text)
