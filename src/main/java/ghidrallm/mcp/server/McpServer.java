package ghidrallm.mcp.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

/**
 * A self-contained Model Context Protocol (MCP) server speaking the Streamable-HTTP
 * transport (JSON-RPC 2.0 over HTTP POST) with no external dependencies beyond the JDK's
 * {@code com.sun.net.httpserver} and the Gson that ships with Ghidra.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code POST /mcp}  - JSON-RPC requests/notifications (single object or batch array).</li>
 *   <li>{@code GET  /mcp}  - 405; this server does not push server-initiated SSE streams.</li>
 *   <li>{@code DELETE /mcp} - 200; session teardown (stateless, so a no-op).</li>
 *   <li>{@code GET  /health} - plain JSON status, handy for scripts and connection checks.</li>
 * </ul>
 *
 * <p>Supported MCP methods: {@code initialize}, {@code ping}, {@code tools/list},
 * {@code tools/call}, and the {@code notifications/*} acknowledgements.
 */
public class McpServer {

	public static final String SERVER_NAME = "GhidraMCP";
	public static final String SERVER_VERSION = "0.1.0";

	/** Protocol revisions we understand; we echo the client's if listed, else offer the newest. */
	private static final List<String> SUPPORTED_PROTOCOLS =
		List.of("2025-06-18", "2025-03-26", "2024-11-05");
	private static final String DEFAULT_PROTOCOL = SUPPORTED_PROTOCOLS.get(0);

	private final String host;
	private final int port;
	private final Map<String, McpTool> tools = new LinkedHashMap<>();
	private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	private final Gson pretty = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
	private final String sessionId = UUID.randomUUID().toString();

	private HttpServer http;
	private ExecutorService executor;

	public McpServer(String host, int port, List<McpTool> toolList) {
		this.host = host;
		this.port = port;
		for (McpTool t : toolList) {
			tools.put(t.name(), t);
		}
	}

	public synchronized void start() throws IOException {
		if (http != null) {
			return;
		}
		http = HttpServer.create(new InetSocketAddress(host, port), 0);
		executor = Executors.newFixedThreadPool(4, r -> {
			Thread t = new Thread(r, "GhidraMCP-http");
			t.setDaemon(true);
			return t;
		});
		http.setExecutor(executor);
		http.createContext("/mcp", this::handleMcp);
		http.createContext("/health", this::handleHealth);
		http.start();
	}

	public synchronized void stop() {
		if (http != null) {
			http.stop(0);
			http = null;
		}
		if (executor != null) {
			executor.shutdownNow();
			executor = null;
		}
	}

	public synchronized boolean isRunning() {
		return http != null;
	}

	public String endpoint() {
		return "http://" + host + ":" + port + "/mcp";
	}

	public int toolCount() {
		return tools.size();
	}

	// --------------------------------------------------------------- HTTP handlers

	private void handleHealth(HttpExchange ex) throws IOException {
		JsonObject o = new JsonObject();
		o.addProperty("server", SERVER_NAME);
		o.addProperty("version", SERVER_VERSION);
		o.addProperty("endpoint", endpoint());
		o.addProperty("tools", tools.size());
		send(ex, 200, gson.toJson(o));
	}

	private void handleMcp(HttpExchange ex) throws IOException {
		String method = ex.getRequestMethod();
		try {
			if ("POST".equalsIgnoreCase(method)) {
				handlePost(ex);
			}
			else if ("DELETE".equalsIgnoreCase(method)) {
				send(ex, 200, "");
			}
			else if ("OPTIONS".equalsIgnoreCase(method)) {
				ex.getResponseHeaders().set("Allow", "POST, DELETE, OPTIONS");
				send(ex, 204, "");
			}
			else { // GET and anything else: no server-initiated stream
				ex.getResponseHeaders().set("Allow", "POST, DELETE, OPTIONS");
				send(ex, 405, errorEnvelope(null, -32000, "This MCP endpoint only accepts POST.").toString());
			}
		}
		catch (Exception e) {
			Msg.error(this, "GhidraMCP request handling failed", e);
			try {
				send(ex, 500, errorEnvelope(null, -32603, "Internal error: " + e.getMessage()).toString());
			}
			catch (IOException ignore) {
				// client went away
			}
		}
		finally {
			ex.close();
		}
	}

	private void handlePost(HttpExchange ex) throws IOException {
		byte[] body;
		try (InputStream in = ex.getRequestBody()) {
			body = in.readAllBytes();
		}
		String text = new String(body, StandardCharsets.UTF_8).trim();

		JsonElement parsed;
		try {
			parsed = text.isEmpty() ? null : JsonParser.parseString(text);
		}
		catch (RuntimeException e) {
			send(ex, 400, errorEnvelope(null, -32700, "Parse error: " + e.getMessage()).toString());
			return;
		}

		if (parsed == null) {
			send(ex, 400, errorEnvelope(null, -32600, "Empty request body.").toString());
			return;
		}

		ex.getResponseHeaders().set("Mcp-Session-Id", sessionId);

		if (parsed.isJsonArray()) {
			JsonArray out = new JsonArray();
			for (JsonElement el : parsed.getAsJsonArray()) {
				JsonObject resp = dispatchSafe(el);
				if (resp != null) {
					out.add(resp);
				}
			}
			if (out.isEmpty()) {
				send(ex, 202, ""); // all notifications
			}
			else {
				send(ex, 200, gson.toJson(out));
			}
			return;
		}

		JsonObject resp = dispatchSafe(parsed);
		if (resp == null) {
			send(ex, 202, ""); // a single notification
		}
		else {
			send(ex, 200, gson.toJson(resp));
		}
	}

	// --------------------------------------------------------------- JSON-RPC dispatch

	/** Never throws; always returns a JSON-RPC response object, or null for a notification. */
	private JsonObject dispatchSafe(JsonElement element) {
		JsonElement id = null;
		try {
			if (!element.isJsonObject()) {
				return errorEnvelope(null, -32600, "Request must be a JSON object.");
			}
			JsonObject msg = element.getAsJsonObject();
			if (msg.has("id") && !msg.get("id").isJsonNull()) {
				id = msg.get("id");
			}
			String method = msg.has("method") && !msg.get("method").isJsonNull()
				? msg.get("method").getAsString()
				: null;
			if (method == null) {
				return errorEnvelope(id, -32600, "Missing 'method'.");
			}
			JsonObject params = msg.has("params") && msg.get("params").isJsonObject()
				? msg.getAsJsonObject("params")
				: new JsonObject();

			boolean isNotification = (id == null);

			switch (method) {
				case "initialize":
					return resultEnvelope(id, initialize(params));
				case "ping":
					return resultEnvelope(id, new JsonObject());
				case "tools/list":
					return resultEnvelope(id, toolsList());
				case "tools/call":
					return resultEnvelope(id, toolsCall(params));
				default:
					if (method.startsWith("notifications/")) {
						return null; // acknowledge silently
					}
					if (isNotification) {
						return null;
					}
					return errorEnvelope(id, -32601, "Method not found: " + method);
			}
		}
		catch (ProtocolError pe) {
			return errorEnvelope(id, pe.code, pe.getMessage());
		}
		catch (Exception e) {
			Msg.error(this, "GhidraMCP dispatch error", e);
			return errorEnvelope(id, -32603, "Internal error: " + e.getMessage());
		}
	}

	private JsonObject initialize(JsonObject params) {
		String requested = params.has("protocolVersion") && !params.get("protocolVersion").isJsonNull()
			? params.get("protocolVersion").getAsString()
			: DEFAULT_PROTOCOL;
		String version = SUPPORTED_PROTOCOLS.contains(requested) ? requested : DEFAULT_PROTOCOL;

		JsonObject result = new JsonObject();
		result.addProperty("protocolVersion", version);

		JsonObject caps = new JsonObject();
		JsonObject toolsCap = new JsonObject();
		toolsCap.addProperty("listChanged", false);
		caps.add("tools", toolsCap);
		result.add("capabilities", caps);

		JsonObject info = new JsonObject();
		info.addProperty("name", SERVER_NAME);
		info.addProperty("version", SERVER_VERSION);
		result.add("serverInfo", info);

		result.addProperty("instructions",
			"Drive Ghidra for reverse engineering, vulnerability assessment and binary patching. " +
			"Call list_open_programs / get_current_program first to see what is loaded, or " +
			"import_binary to load a file. Most tools accept an optional 'program' name; when " +
			"omitted they act on the program currently active in Ghidra.");
		return result;
	}

	private JsonObject toolsList() {
		JsonArray arr = new JsonArray();
		for (McpTool t : tools.values()) {
			JsonObject o = new JsonObject();
			o.addProperty("name", t.name());
			o.addProperty("description", t.description());
			o.add("inputSchema", t.inputSchema());
			arr.add(o);
		}
		JsonObject result = new JsonObject();
		result.add("tools", arr);
		return result;
	}

	private JsonObject toolsCall(JsonObject params) throws ProtocolError {
		String name = params.has("name") && !params.get("name").isJsonNull()
			? params.get("name").getAsString()
			: null;
		if (name == null) {
			throw new ProtocolError(-32602, "tools/call requires a 'name'.");
		}
		McpTool tool = tools.get(name);
		if (tool == null) {
			throw new ProtocolError(-32602, "Unknown tool: " + name);
		}
		JsonObject args = params.has("arguments") && params.get("arguments").isJsonObject()
			? params.getAsJsonObject("arguments")
			: new JsonObject();

		try {
			String payload = tool.handler().handle(args);
			return toolResult(payload == null ? "" : payload, false);
		}
		catch (ToolException te) {
			return toolResult("Error: " + te.getMessage(), true);
		}
		catch (Exception e) {
			Msg.error(this, "GhidraMCP tool '" + name + "' failed", e);
			String cls = e.getClass().getSimpleName();
			return toolResult("Error (" + cls + "): " + (e.getMessage() == null ? cls : e.getMessage()), true);
		}
	}

	private JsonObject toolResult(String text, boolean isError) {
		JsonObject item = new JsonObject();
		item.addProperty("type", "text");
		item.addProperty("text", text);
		JsonArray content = new JsonArray();
		content.add(item);
		JsonObject result = new JsonObject();
		result.add("content", content);
		result.addProperty("isError", isError);
		return result;
	}

	// --------------------------------------------------------------- envelopes

	private JsonObject resultEnvelope(JsonElement id, JsonObject result) {
		JsonObject o = new JsonObject();
		o.addProperty("jsonrpc", "2.0");
		o.add("id", id == null ? com.google.gson.JsonNull.INSTANCE : id);
		o.add("result", result);
		return o;
	}

	private JsonObject errorEnvelope(JsonElement id, int code, String message) {
		JsonObject err = new JsonObject();
		err.addProperty("code", code);
		err.addProperty("message", message);
		JsonObject o = new JsonObject();
		o.addProperty("jsonrpc", "2.0");
		o.add("id", id == null ? com.google.gson.JsonNull.INSTANCE : id);
		o.add("error", err);
		return o;
	}

	// --------------------------------------------------------------- util

	private void send(HttpExchange ex, int status, String body) throws IOException {
		byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
		if (bytes.length == 0) {
			ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
			ex.sendResponseHeaders(status, -1);
			return;
		}
		ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		ex.sendResponseHeaders(status, bytes.length);
		try (OutputStream os = ex.getResponseBody()) {
			os.write(bytes);
		}
	}

	/** Unused helper kept for symmetry; pretty-prints a JSON element. */
	String pretty(JsonElement e) {
		return pretty.toJson(e);
	}

	private static final class ProtocolError extends Exception {
		final int code;

		ProtocolError(int code, String message) {
			super(message);
			this.code = code;
		}
	}
}
