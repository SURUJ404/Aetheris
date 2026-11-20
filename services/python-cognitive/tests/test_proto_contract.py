"""Contract tests for generated `agentic.v1` Python bindings."""

from app.gen.agentic.v1 import cognitive_pb2, cognitive_pb2_grpc


def test_plan_request_field_numbers_are_stable() -> None:
    fields = cognitive_pb2.PlanRequest.DESCRIPTOR.fields_by_name
    assert fields["context"].number == 1
    assert fields["user_input"].number == 2
    assert fields["serialized_context"].number == 3
    assert fields["max_steps"].number == 4
    assert fields["budget"].number == 5
    assert fields["tool_catalog"].number == 6


def test_request_context_and_budget_fields() -> None:
    context = cognitive_pb2.RequestContext.DESCRIPTOR.fields_by_name
    assert context["tenant_id"].number == 3
    assert context["traceparent"].number == 5
    assert context["idempotency_key"].number == 8
    assert context["policy_version"].number == 9

    budget = cognitive_pb2.Budget.DESCRIPTOR.fields_by_name
    assert budget["max_tokens"].number == 1
    assert budget["max_cost_micros"].number == 2
    assert budget["max_wall_clock_ms"].number == 3
    assert budget["max_tool_calls"].number == 4


def test_plan_request_roundtrip() -> None:
    request = cognitive_pb2.PlanRequest(
        context=cognitive_pb2.RequestContext(
            request_id="req-1",
            task_id="task-1",
            tenant_id="tenant-1",
            actor_id="actor-1",
            traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            idempotency_key="idem-1",
            policy_version="2026-11-19.rbac-v1",
        ),
        user_input="Summarize the incident",
        max_steps=8,
        budget=cognitive_pb2.Budget(
            max_tokens=4096,
            max_cost_micros=25_000,
            max_wall_clock_ms=30_000,
            max_tool_calls=4,
        ),
    )

    decoded = cognitive_pb2.PlanRequest.FromString(request.SerializeToString())
    assert decoded == request
    assert decoded.context.tenant_id == "tenant-1"
    assert decoded.budget.max_tool_calls == 4


def test_service_bindings_exist() -> None:
    assert hasattr(cognitive_pb2_grpc, "CognitiveServiceStub")
    assert hasattr(cognitive_pb2_grpc, "CognitiveServiceServicer")
    assert hasattr(cognitive_pb2_grpc, "add_CognitiveServiceServicer_to_server")


def test_risk_level_values_are_stable() -> None:
    assert cognitive_pb2.RISK_LEVEL_UNSPECIFIED == 0
    assert cognitive_pb2.RISK_LEVEL_LOW == 1
    assert cognitive_pb2.RISK_LEVEL_MEDIUM == 2
    assert cognitive_pb2.RISK_LEVEL_HIGH == 3
    assert cognitive_pb2.RISK_LEVEL_CRITICAL == 4
