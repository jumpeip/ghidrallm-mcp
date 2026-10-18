package ghidrallm.mcp.ops;

import java.util.List;

import com.google.gson.JsonObject;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidrallm.mcp.server.ToolException;

/**
 * Thin bridge between tool handlers and the running Ghidra tool: program resolution,
 * address parsing, transaction and Swing-thread helpers, and JSON argument accessors.
 */
public class GhidraBridge {

	private final PluginTool tool;

	public GhidraBridge(PluginTool tool) {
		this.tool = tool;
	}

	public PluginTool tool() {
		return tool;
	}

	public ProgramManager programManager() {
		return tool.getService(ProgramManager.class);
	}

	public Program current() {
		ProgramManager pm = programManager();
		return pm == null ? null : pm.getCurrentProgram();
	}

	public Program[] openPrograms() {
		ProgramManager pm = programManager();
		return pm == null ? new Program[0] : pm.getAllOpenPrograms();
	}

	/**
	 * Resolves the program a tool call targets: the optional {@code program} argument matched
	 * against open program names or project paths, else the currently active program.
	 */
	public Program resolve(JsonObject args) throws ToolException {
		String name = str(args, "program", null);
		if (name == null || name.isBlank()) {
			Program c = current();
			if (c == null) {
				throw new ToolException("No program is open in Ghidra. Load one with import_binary, " +
					"or open a program in the tool, then retry.");
			}
			return c;
		}
		for (Program p : openPrograms()) {
			if (p.getName().equals(name)) {
				return p;
			}
			try {
				if (p.getDomainFile() != null && name.equals(p.getDomainFile().getPathname())) {
					return p;
				}
			}
			catch (Exception ignore) {
				// domain file may be unavailable; fall through
			}
		}
		throw new ToolException("No open program matches '" + name +
			"'. Call list_open_programs to see available names.");
	}

	public Address address(Program p, String spec) throws ToolException {
		if (spec == null || spec.isBlank()) {
			throw new ToolException("Missing 'address'.");
		}
		try {
			Address a = p.getAddressFactory().getAddress(spec.trim());
			if (a == null) {
				throw new ToolException("Could not parse address '" + spec + "'.");
			}
			return a;
		}
		catch (ToolException te) {
			throw te;
		}
		catch (Exception e) {
			throw new ToolException("Could not parse address '" + spec + "': " + e.getMessage());
		}
	}

	/**
	 * Resolves a function from the {@code address} (any address inside it) or {@code name}
	 * argument. Shared by all function-oriented tools.
	 */
	public Function resolveFunction(Program p, JsonObject args) throws ToolException {
		String addr = str(args, "address", null);
		if (addr != null && !addr.isBlank()) {
			Address a = address(p, addr);
			Function f = p.getFunctionManager().getFunctionContaining(a);
			if (f == null) {
				f = p.getFunctionManager().getFunctionAt(a);
			}
			if (f == null) {
				throw new ToolException("No function at or containing " + addr + ".");
			}
			return f;
		}
		String name = str(args, "name", null);
		if (name != null && !name.isBlank()) {
			List<Function> fs = p.getListing().getGlobalFunctions(name);
			if (fs.isEmpty()) {
				throw new ToolException("No function named '" + name + "'.");
			}
			return fs.get(0);
		}
		throw new ToolException("Provide 'address' or 'name' to identify the function.");
	}

	/** Resolves a data-type string (e.g. {@code int}, {@code char[16]}, {@code MyStruct *}). */
	public DataType parseDataType(Program p, String typeStr) throws ToolException {
		DataTypeManager dtm = p.getDataTypeManager();
		DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
		try {
			DataType dt = parser.parse(typeStr);
			if (dt == null) {
				throw new ToolException("Unknown data type: '" + typeStr + "'.");
			}
			return dt;
		}
		catch (ToolException te) {
			throw te;
		}
		catch (Exception e) {
			throw new ToolException("Could not resolve data type '" + typeStr + "': " + e.getMessage());
		}
	}

	// ------------------------------------------------------------ execution helpers

	public interface TxBody<T> {
		T run() throws Exception;
	}

	/** Runs {@code body} inside a program transaction, committing on success. */
	public <T> T inTransaction(Program p, String description, TxBody<T> body) throws Exception {
		int txId = p.startTransaction(description);
		boolean commit = false;
		try {
			T result = body.run();
			commit = true;
			return result;
		}
		finally {
			p.endTransaction(txId, commit);
		}
	}

	public interface SwingBody<T> {
		T run() throws Exception;
	}

	/** Runs {@code body} synchronously on the Swing thread, propagating any exception. */
	public <T> T onSwing(SwingBody<T> body) throws Exception {
		final Object[] out = new Object[1];
		final Exception[] err = new Exception[1];
		Swing.runNow(() -> {
			try {
				out[0] = body.run();
			}
			catch (Exception e) {
				err[0] = e;
			}
		});
		if (err[0] != null) {
			throw err[0];
		}
		@SuppressWarnings("unchecked")
		T result = (T) out[0];
		return result;
	}

	// ------------------------------------------------------------ JSON argument accessors

	public static String str(JsonObject o, String key, String def) {
		return (o != null && o.has(key) && !o.get(key).isJsonNull()) ? o.get(key).getAsString() : def;
	}

	public static String reqStr(JsonObject o, String key) throws ToolException {
		String v = str(o, key, null);
		if (v == null || v.isBlank()) {
			throw new ToolException("Missing required argument '" + key + "'.");
		}
		return v;
	}

	public static int intArg(JsonObject o, String key, int def) {
		return (o != null && o.has(key) && !o.get(key).isJsonNull()) ? o.get(key).getAsInt() : def;
	}

	public static long longArg(JsonObject o, String key, long def) {
		return (o != null && o.has(key) && !o.get(key).isJsonNull()) ? o.get(key).getAsLong() : def;
	}

	public static boolean boolArg(JsonObject o, String key, boolean def) {
		return (o != null && o.has(key) && !o.get(key).isJsonNull()) ? o.get(key).getAsBoolean() : def;
	}

	/** Parses a long from decimal or 0x-prefixed hex text. */
	public static long longFromStr(String s) throws ToolException {
		String t = s.trim();
		try {
			return Long.decode(t);
		}
		catch (NumberFormatException e) {
			// Long.decode rejects values with the sign bit set; fall back to unsigned hex.
			try {
				if (t.toLowerCase().startsWith("0x")) {
					return Long.parseUnsignedLong(t.substring(2), 16);
				}
				return Long.parseUnsignedLong(t, 10);
			}
			catch (NumberFormatException e2) {
				throw new ToolException("Not a valid integer: '" + s + "'.");
			}
		}
	}
}
