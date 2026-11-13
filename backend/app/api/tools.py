from fastapi import APIRouter, HTTPException, Query, status

from app.database.store import database
from app.tools.models import (
    MCPResourceMetadata,
    MCPResourceRequest,
    MCPServer,
    ToolDefinition,
    ToolExecutionAudit,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolRegistration,
    ToolSecurityTestRequest,
    ToolSecurityTestResult,
)
from app.tools.service import ToolService

router = APIRouter(tags=["Synthetic Tools and MCP"])
tool_service = ToolService(database)


@router.get("/tools", response_model=list[ToolDefinition])
def list_tools() -> list[ToolDefinition]:
    return tool_service.list_tools()


@router.post(
    "/tools/register",
    response_model=ToolDefinition,
    status_code=status.HTTP_201_CREATED,
)
def register_tool(registration: ToolRegistration) -> ToolDefinition:
    return tool_service.register_tool(registration)


@router.post(
    "/tools/{tool_id}/invoke",
    response_model=ToolInvocationResult,
    status_code=status.HTTP_201_CREATED,
)
def invoke_tool(tool_id: str, request: ToolInvocationRequest) -> ToolInvocationResult:
    try:
        return tool_service.invoke(tool_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/tools/executions", response_model=list[ToolExecutionAudit])
def list_tool_executions(
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ToolExecutionAudit]:
    return tool_service.list_executions(limit)


@router.post(
    "/tools/security-tests",
    response_model=ToolSecurityTestResult,
    status_code=status.HTTP_201_CREATED,
)
def run_tool_security_test(
    request: ToolSecurityTestRequest,
) -> ToolSecurityTestResult:
    return tool_service.run_security_test(request)


@router.get("/tools/security-tests", response_model=list[ToolSecurityTestResult])
def list_tool_security_results(
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ToolSecurityTestResult]:
    return tool_service.list_security_results(limit)


@router.get("/tools/{tool_id}", response_model=ToolDefinition)
def get_tool(tool_id: str) -> ToolDefinition:
    tool = tool_service.get_tool(tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Synthetic tool not found.")
    return tool


@router.get("/mcp/servers", response_model=list[MCPServer])
def list_mcp_servers() -> list[MCPServer]:
    return tool_service.list_servers()


@router.get("/mcp/servers/{server_id}", response_model=MCPServer)
def get_mcp_server(server_id: str) -> MCPServer:
    server = database.get_mcp_server(server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Synthetic MCP server not found.")
    return server


@router.get("/mcp/resources", response_model=list[MCPResourceMetadata])
def list_mcp_resources(
    server_id: str | None = None,
) -> list[MCPResourceMetadata]:
    return tool_service.list_mcp_resources(server_id)


@router.post(
    "/mcp/resources/{resource_id}/retrieve",
    status_code=status.HTTP_200_OK,
)
def retrieve_mcp_resource(
    resource_id: str,
    request: MCPResourceRequest,
) -> dict[str, object]:
    try:
        return tool_service.retrieve_mcp_resource(resource_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/mcp/tools/{tool_id}/invoke",
    response_model=ToolInvocationResult,
    status_code=status.HTTP_201_CREATED,
)
def invoke_mcp_tool(
    tool_id: str,
    request: ToolInvocationRequest,
) -> ToolInvocationResult:
    return invoke_tool(tool_id, request)
