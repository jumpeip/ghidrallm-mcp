package ghidrallm.mcp.server;

import com.google.gson.JsonObject;

/**
 * One MCP tool: its name, human/LLM-facing description, JSON-Schema for its arguments,
 * and the handler that executes it.
 *
 * <p>The handler receives the parsed {@code arguments} object (never null) and returns a
 * text payload (plain text or a JSON string) that becomes the tool-call result content.
 * It may throw {@link ToolException} for expected errors or any other exception for
 * unexpected ones; both are surfaced to the client as an error result.
 */
public record McpTool(String name, String description, JsonObject inputSchema, Handler handler) {

	@FunctionalInterface
	public interface Handler {
		String handle(JsonObject arguments) throws Exception;
	}
}
