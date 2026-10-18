package ghidrallm.mcp;

import java.io.IOException;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import docking.action.builder.ActionBuilder;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidrallm.mcp.ops.GhidraBridge;
import ghidrallm.mcp.ops.ToolCatalog;
import ghidrallm.mcp.server.McpServer;
import ghidrallm.mcp.server.McpTool;

/**
 * GhidraMCP: embeds a Model Context Protocol server inside Ghidra so external LLM agents
 * (Claude Code, Codex, Cline, or any MCP client) can drive Ghidra for reverse engineering,
 * vulnerability assessment and binary patching.
 *
 * <p>The server listens on a localhost HTTP endpoint ({@code http://127.0.0.1:8765/mcp} by
 * default) and speaks the MCP Streamable-HTTP transport directly &mdash; no Python bridge.
 * Connect a client with, e.g.:
 * <pre>claude mcp add --transport http ghidra http://127.0.0.1:8765/mcp</pre>
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "MCP server exposing Ghidra to LLM agents",
	description = "Embeds a Model Context Protocol (MCP) server inside Ghidra, served over a " +
		"localhost Streamable-HTTP JSON-RPC endpoint. Lets external LLM agents import and analyze " +
		"binaries, control which analyzers run, decompile and disassemble, query functions, " +
		"symbols, strings, imports/exports and cross-references, rename and comment, and patch " +
		"binaries (raw bytes or assembled instructions)."
)
//@formatter:on
public class GhidraMcpPlugin extends ProgramPlugin {

	public static final String MENU = "GhidraMCP";
	private static final String OPTIONS = "GhidraMCP";

	private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

	private McpServer server;
	private int port = 8765;
	private String bindHost = "127.0.0.1";
	private boolean autoStart = true;

	public GhidraMcpPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		readOptions();
		createActions();
		if (autoStart) {
			startServer(false);
		}
	}

	@Override
	protected void dispose() {
		stopServer(false);
		super.dispose();
	}

	// ------------------------------------------------------------ options

	private void readOptions() {
		Options o = tool.getOptions(OPTIONS);
		o.registerOption("Port", 8765, null,
			"TCP port for the MCP HTTP endpoint.");
		o.registerOption("Bind Address", "127.0.0.1", null,
			"Interface to bind. Keep 127.0.0.1 (localhost) unless you fully understand the exposure; " +
				"the endpoint is unauthenticated.");
		o.registerOption("Auto-start", true, null,
			"Start the MCP server automatically when a tool with this plugin opens.");
		port = o.getInt("Port", 8765);
		bindHost = o.getString("Bind Address", "127.0.0.1");
		autoStart = o.getBoolean("Auto-start", true);
	}

	// ------------------------------------------------------------ actions

	private void createActions() {
		String owner = getName();

		// Both actions stay enabled; the handlers no-op (and inform) if already in that
		// state. Ghidra only re-evaluates enabledWhen() predicates on context changes, not
		// when the server field flips, which would otherwise leave Start stale-disabled
		// after a Stop.
		new ActionBuilder("GhidraMCP Start Server", owner)
				.menuPath(MENU, "Start MCP Server")
				.menuGroup("1_server", "a")
				.description("Start the embedded MCP HTTP server")
				.enabled(true)
				.onAction(c -> startServer(true))
				.buildAndInstall(tool);

		new ActionBuilder("GhidraMCP Stop Server", owner)
				.menuPath(MENU, "Stop MCP Server")
				.menuGroup("1_server", "b")
				.description("Stop the embedded MCP HTTP server")
				.enabled(true)
				.onAction(c -> stopServer(true))
				.buildAndInstall(tool);

		new ActionBuilder("GhidraMCP Status", owner)
				.menuPath(MENU, "Server Status...")
				.menuGroup("2_info")
				.description("Show the MCP server status and endpoint URL")
				.onAction(c -> showStatus())
				.buildAndInstall(tool);
	}

	// ------------------------------------------------------------ server lifecycle

	private void startServer(boolean interactive) {
		if (server != null && server.isRunning()) {
			if (interactive) {
				Msg.showInfo(this, tool.getActiveWindow(), MENU,
					"MCP server is already running at " + server.endpoint());
			}
			return;
		}
		try {
			GhidraBridge bridge = new GhidraBridge(tool);
			List<McpTool> tools = ToolCatalog.build(bridge, gson);
			server = new McpServer(bindHost, port, tools);
			server.start();
			String msg = "GhidraMCP listening at " + server.endpoint() + " (" + server.toolCount() +
				" tools)";
			Msg.info(this, msg);
			tool.setStatusInfo(msg);
			if (interactive) {
				Msg.showInfo(this, tool.getActiveWindow(), MENU, msg);
			}
		}
		catch (IOException e) {
			server = null;
			String msg = "Could not start MCP server on " + bindHost + ":" + port +
				" - " + e.getMessage() + "\n\nChange the port in Edit > Tool Options > " + OPTIONS +
				" and try again.";
			Msg.showError(this, tool.getActiveWindow(), MENU, msg, e);
		}
	}

	private void stopServer(boolean interactive) {
		if (server == null || !server.isRunning()) {
			if (interactive) {
				Msg.showInfo(this, tool.getActiveWindow(), MENU, "MCP server is not running.");
			}
			return;
		}
		String endpoint = server.endpoint();
		server.stop();
		server = null;
		Msg.info(this, "GhidraMCP stopped (" + endpoint + ")");
		tool.setStatusInfo("GhidraMCP stopped");
		if (interactive) {
			Msg.showInfo(this, tool.getActiveWindow(), MENU, "MCP server stopped.");
		}
	}

	private void showStatus() {
		StringBuilder sb = new StringBuilder();
		if (server != null && server.isRunning()) {
			sb.append("Status: RUNNING\n");
			sb.append("Endpoint: ").append(server.endpoint()).append('\n');
			sb.append("Tools: ").append(server.toolCount()).append('\n');
		}
		else {
			sb.append("Status: STOPPED\n");
			sb.append("Configured endpoint: http://").append(bindHost).append(':').append(port)
					.append("/mcp\n");
		}
		sb.append('\n');
		sb.append("Connect a client, e.g.:\n");
		sb.append("  claude mcp add --transport http ghidra http://").append(bindHost).append(':')
				.append(port).append("/mcp");
		Msg.showInfo(this, tool.getActiveWindow(), MENU + " Status", sb.toString());
	}
}
