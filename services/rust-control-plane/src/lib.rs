//! Rust control plane for the agentic platform.
//!
//! Authority rules:
//! - Rust owns identity, authorization, policy, budgets and execution state.
//! - Python proposes plans; Rust validates and authorizes every action.
//! - All privileged tool execution passes through the broker and a runtime.

pub mod api;
pub mod auth;
pub mod broker;
pub mod config;
pub mod execution;
pub mod observability;
pub mod persistence;
pub mod policy;
pub mod proto;
pub mod runtime;
pub mod state;
