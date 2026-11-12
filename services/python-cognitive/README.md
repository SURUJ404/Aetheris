# Python Cognitive Service

Responsibilities: context assembly, retrieval, planning, reasoning and evaluation.
Non-responsibilities: user authorization, budget authority, privileged tool execution,
or durable execution-state ownership.

The service receives authenticated internal gRPC requests from Rust and returns
structured proposals conforming to versioned protobuf contracts.
