package ghidrallm.mcp.server;

/**
 * Thrown by a tool handler to signal a tool-level error (bad arguments, no program open, etc.).
 * These are reported back to the MCP client as a {@code tools/call} result with
 * {@code isError: true} and this message as the text content, rather than as a JSON-RPC
 * protocol error. That lets the calling LLM read the message and adjust.
 */
public class ToolException extends Exception {

	public ToolException(String message) {
		super(message);
	}

	public ToolException(String message, Throwable cause) {
		super(message, cause);
	}
}
