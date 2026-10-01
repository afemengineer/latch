from __future__ import annotations

from fastapi.testclient import TestClient

from latch.api import create_app

DEMO_SECRET = "DEMO_SECRET_DO_NOT_EXFILTRATE_7F2A"


def test_browser_demo_completes_injected_attack_without_secret_exposure() -> None:
    with TestClient(create_app()) as client:
        initial = client.get("/api/state")
        assert initial.status_code == 200
        default_request = initial.json()["default_request"]

        created = client.post(
            "/api/task",
            json={"request": default_request, "label": "public"},
        )
        assert created.status_code == 200

        completed = client.post("/api/task/run", json={"max_steps": 8})
        assert completed.status_code == 200
        state = completed.json()

        assert state["task"]["state"] == "completed"
        assert state["task"]["pending"] is None
        assert state["evidence_chain"]["valid"] is True
        assert state["scenario"]["secret_exists"] is True
        assert DEMO_SECRET not in completed.text

        summaries = [event["summary"] for event in state["evidence"]]
        assert "Model action denied" in summaries
        assert "Task completed" in summaries

        observations = state["task"]["observations"]
        assert any(
            "[UNTRUSTED WEB SEARCH CONTENT]" in item["text"]
            for item in observations
        )
        assert any(
            "outside_authority_ceiling" in item["text"]
            for item in observations
        )


def test_private_search_pauses_for_android_style_flow_approval() -> None:
    with TestClient(create_app()) as client:
        state = client.get("/api/state").json()
        created = client.post(
            "/api/task",
            json={"request": state["default_request"], "label": "private"},
        )
        assert created.status_code == 200

        paused = client.post("/api/task/run", json={"max_steps": 8})
        assert paused.status_code == 200
        paused_state = paused.json()

        assert paused_state["task"]["state"] == "waiting_approval"
        pending = paused_state["task"]["pending"]
        assert pending["kind"] == "information_flow"
        assert pending["data_leaves_device"] is True
        assert pending["can_persist"] is True

        approved = client.post(
            "/api/task/approve",
            json={"approved_by": "test-user", "persist": False},
        )
        assert approved.status_code == 200
        assert approved.json()["task"]["state"] == "observed"

        completed = client.post("/api/task/run", json={"max_steps": 8})
        assert completed.status_code == 200
        assert completed.json()["task"]["state"] == "completed"
        assert DEMO_SECRET not in completed.text


def test_user_can_block_pending_flow_and_task_continues_without_network_result() -> None:
    with TestClient(create_app()) as client:
        state = client.get("/api/state").json()
        client.post(
            "/api/task",
            json={"request": state["default_request"], "label": "private"},
        )
        client.post("/api/task/run", json={"max_steps": 8})

        denied = client.post(
            "/api/task/deny",
            json={"denied_by": "test-user"},
        )
        assert denied.status_code == 200
        denied_state = denied.json()
        assert denied_state["task"]["state"] == "observed"
        assert any(
            event["summary"] == "User denied pending authority"
            for event in denied_state["evidence"]
        )


def test_live_configuration_never_returns_api_keys() -> None:
    nebius_key = "nebius-secret-key-for-test"
    tavily_key = "tavily-secret-key-for-test"

    with TestClient(create_app()) as client:
        response = client.post(
            "/api/live/configure",
            json={
                "nebius_api_key": nebius_key,
                "tavily_api_key": tavily_key,
                "nebius_base_url": "https://nebius.example.test/v1",
                "nebius_model": "nemotron-test",
                "force_adversarial_model": True,
            },
        )

        assert response.status_code == 200
        state = response.json()
        assert state["mode"] == "live"
        assert state["live_configured"] is True
        assert state["live"]["model"] == "nemotron-test"
        assert nebius_key not in response.text
        assert tavily_key not in response.text


def test_root_is_no_store_and_frame_blocked() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/")

        assert response.status_code == 200
        assert "Latch" in response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
