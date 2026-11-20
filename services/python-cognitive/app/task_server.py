"""Async TaskService server entry point."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import grpc

from app.gen.agentic.v1 import task_service_pb2_grpc
from app.task_service import InMemoryTaskRepository, TaskServiceServicer


async def serve() -> None:
    token = os.environ["TASK_SERVICE_INTERNAL_TOKEN"]
    address = os.getenv("TASK_SERVICE_BIND_ADDRESS", "0.0.0.0:50052")
    server = grpc.aio.server()
    task_service_pb2_grpc.add_TaskServiceServicer_to_server(
        TaskServiceServicer(InMemoryTaskRepository(), internal_token=token),
        server,
    )
    certificate_path = os.getenv("TASK_SERVICE_TLS_CERT")
    key_path = os.getenv("TASK_SERVICE_TLS_KEY")
    if bool(certificate_path) != bool(key_path):
        raise ValueError("TASK_SERVICE_TLS_CERT and TASK_SERVICE_TLS_KEY must be configured together")
    if certificate_path and key_path:
        certificate = Path(certificate_path).read_bytes()
        private_key = Path(key_path).read_bytes()
        credentials = grpc.ssl_server_credentials(((private_key, certificate),))
        server.add_secure_port(address, credentials)
    elif os.getenv("TASK_SERVICE_ALLOW_INSECURE", "true").lower() == "true":
        server.add_insecure_port(address)
    else:
        raise ValueError("TLS is required unless TASK_SERVICE_ALLOW_INSECURE=true")
    await server.start()
    await server.wait_for_termination()


def main() -> None:
    asyncio.run(serve())


if __name__ == "__main__":
    main()
