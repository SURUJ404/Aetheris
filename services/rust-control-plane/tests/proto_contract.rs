//! Contract tests for the `agentic.v1` protobuf surface.
//!
//! These tests intentionally pin field numbers and wire encoding. Renumbering a
//! field is a breaking change and must fail this test suite.

use prost::Message;
use rust_control_plane::proto::{
    ApprovalHint, Budget, PlanRequest, PlanResponse, ProposedAction, RequestContext, RiskLevel,
    ToolCatalogRef, Usage,
};

fn sample_request() -> PlanRequest {
    PlanRequest {
        context: Some(RequestContext {
            request_id: "req-1".into(),
            task_id: "task-1".into(),
            tenant_id: "tenant-1".into(),
            actor_id: "actor-1".into(),
            traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into(),
            tracestate: "vendor=value".into(),
            attempt: 2,
            idempotency_key: "idem-1".into(),
        }),
        user_input: "Summarize the incident".into(),
        serialized_context: r#"{"documents":[]}"#.into(),
        max_steps: 8,
        budget: Some(Budget {
            max_tokens: 4096,
            max_cost_micros: 25_000,
            max_wall_clock_ms: 30_000,
            max_tool_calls: 4,
        }),
        tool_catalog: Some(ToolCatalogRef {
            catalog_version: "2026-11-12".into(),
            allowed_tools: vec!["search".into(), "read_file".into()],
            schema_hash: "abc123".into(),
        }),
        locale: "en-US".into(),
        metadata: [("channel".to_string(), "api".to_string())].into(),
    }
}

#[test]
fn plan_request_roundtrip_preserves_all_fields() {
    let request = sample_request();
    let decoded = PlanRequest::decode(request.encode_to_vec().as_slice()).expect("decode");

    assert_eq!(decoded, request);
    assert_eq!(decoded.context.as_ref().unwrap().tenant_id, "tenant-1");
    assert_eq!(decoded.budget.as_ref().unwrap().max_tool_calls, 4);
    assert_eq!(
        decoded.tool_catalog.as_ref().unwrap().allowed_tools,
        vec!["search", "read_file"]
    );
}

#[test]
fn plan_request_field_numbers_are_stable() {
    // max_steps = 4, varint => tag byte (4 << 3) | 0 = 0x20
    let bytes = PlanRequest {
        max_steps: 7,
        ..Default::default()
    }
    .encode_to_vec();
    assert_eq!(bytes, vec![0x20, 0x07]);

    // RequestContext.tenant_id = 3, string => tag byte (3 << 3) | 2 = 0x1a
    let bytes = RequestContext {
        tenant_id: "t1".into(),
        ..Default::default()
    }
    .encode_to_vec();
    assert_eq!(bytes, vec![0x1a, 0x02, b't', b'1']);

    // Budget.max_cost_micros = 2, varint => 0x10
    let bytes = Budget {
        max_cost_micros: 5,
        ..Default::default()
    }
    .encode_to_vec();
    assert_eq!(bytes, vec![0x10, 0x05]);
}

#[test]
fn plan_response_roundtrip_preserves_actions_and_approval() {
    let response = PlanResponse {
        task_id: "task-1".into(),
        actions: vec![ProposedAction {
            step_id: "step-1".into(),
            tool_name: "search".into(),
            arguments_json: r#"{"query":"incident"}"#.into(),
            rationale: "Need the incident timeline".into(),
            tool_version: "1".into(),
            depends_on: vec![],
            risk: RiskLevel::Low as i32,
            expected_effect: "Read-only retrieval".into(),
        }],
        final_response: "Proposed plan".into(),
        requires_human_review: false,
        usage: Some(Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
            cost_micros: 1_000,
            wall_clock_ms: 250,
        }),
        warnings: vec![],
        plan_id: "plan-1".into(),
        risk: RiskLevel::Low as i32,
        approval: Some(ApprovalHint {
            required: false,
            reason: String::new(),
            risk: RiskLevel::Low as i32,
        }),
    };

    let decoded = PlanResponse::decode(response.encode_to_vec().as_slice()).expect("decode");
    assert_eq!(decoded, response);
    assert_eq!(decoded.actions[0].tool_name, "search");
}

#[test]
fn generated_grpc_client_type_is_available() {
    let name = std::any::type_name::<
        rust_control_plane::proto::cognitive_service_client::CognitiveServiceClient<
            tonic::transport::Channel,
        >,
    >();
    assert!(name.contains("CognitiveServiceClient"));
}

#[test]
fn risk_level_values_are_stable() {
    assert_eq!(RiskLevel::Unspecified as i32, 0);
    assert_eq!(RiskLevel::Low as i32, 1);
    assert_eq!(RiskLevel::Medium as i32, 2);
    assert_eq!(RiskLevel::High as i32, 3);
    assert_eq!(RiskLevel::Critical as i32, 4);
}
