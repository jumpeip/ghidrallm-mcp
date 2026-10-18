package ghidrallm.mcp.ops;

import java.util.List;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.Options;
import ghidra.framework.options.OptionType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallm.mcp.server.ToolException;

/**
 * Auto-analysis control: run analysis, and inspect/toggle individual analyzers and their
 * options (the "Analyzers" program option group).
 */
public class AnalysisOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public AnalysisOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	/** Runs (or re-runs) full auto-analysis on a program. Shared with import_binary. */
	static String runAnalysis(GhidraBridge bridge, Program program) throws Exception {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		bridge.inTransaction(program, "Auto-analysis (MCP)", () -> {
			mgr.initializeOptions();
			mgr.reAnalyzeAll(null);
			mgr.startAnalysis(TaskMonitor.DUMMY);
			return null;
		});
		return "analysis complete; functions=" + program.getFunctionManager().getFunctionCount() +
			", symbols=" + program.getSymbolTable().getNumSymbols();
	}

	public String analyzeProgram(JsonObject args) throws Exception {
		Program program = bridge.resolve(args);
		String note = runAnalysis(bridge, program);
		JsonObject o = new JsonObject();
		o.addProperty("program", program.getName());
		o.addProperty("result", note);
		o.addProperty("functionCount", program.getFunctionManager().getFunctionCount());
		o.addProperty("symbolCount", program.getSymbolTable().getNumSymbols());
		return gson.toJson(o);
	}

	public String listAnalyzers(JsonObject args) throws Exception {
		Program program = bridge.resolve(args);
		Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		JsonArray arr = new JsonArray();
		for (String name : opts.getOptionNames()) {
			// Top-level booleans (no dotted sub-path) are the per-analyzer on/off toggles.
			if (name.contains(".")) {
				continue;
			}
			if (opts.getType(name) != OptionType.BOOLEAN_TYPE) {
				continue;
			}
			JsonObject a = new JsonObject();
			a.addProperty("name", name);
			a.addProperty("enabled", opts.getBoolean(name, false));
			String desc = opts.getDescription(name);
			if (desc != null && !desc.isBlank()) {
				a.addProperty("description", desc);
			}
			arr.add(a);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", program.getName());
		o.addProperty("count", arr.size());
		o.add("analyzers", arr);
		return gson.toJson(o);
	}

	public String setAnalyzerEnabled(JsonObject args) throws Exception {
		Program program = bridge.resolve(args);
		String name = GhidraBridge.reqStr(args, "analyzer");
		boolean enabled = GhidraBridge.boolArg(args, "enabled", true);
		Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		if (!opts.contains(name) || opts.getType(name) != OptionType.BOOLEAN_TYPE) {
			throw new ToolException("No analyzer toggle named '" + name +
				"'. Call list_analyzers for exact names.");
		}
		bridge.inTransaction(program, "Set analyzer enabled (MCP)",
			() -> {
				opts.setBoolean(name, enabled);
				return null;
			});
		JsonObject o = new JsonObject();
		o.addProperty("analyzer", name);
		o.addProperty("enabled", opts.getBoolean(name, enabled));
		return gson.toJson(o);
	}

	public String getAnalysisOptions(JsonObject args) throws Exception {
		Program program = bridge.resolve(args);
		String filter = GhidraBridge.str(args, "filter", null);
		Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		JsonArray arr = new JsonArray();
		for (String name : opts.getOptionNames()) {
			if (filter != null && !name.toLowerCase().contains(filter.toLowerCase())) {
				continue;
			}
			JsonObject a = new JsonObject();
			a.addProperty("name", name);
			a.addProperty("type", String.valueOf(opts.getType(name)));
			Object v = opts.getObject(name, null);
			a.addProperty("value", v == null ? null : String.valueOf(v));
			arr.add(a);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", program.getName());
		o.addProperty("count", arr.size());
		o.add("options", arr);
		return gson.toJson(o);
	}

	public String setAnalysisOption(JsonObject args) throws Exception {
		Program program = bridge.resolve(args);
		String name = GhidraBridge.reqStr(args, "name");
		String value = GhidraBridge.reqStr(args, "value");
		Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		if (!opts.contains(name)) {
			throw new ToolException("No analysis option named '" + name +
				"'. Call get_analysis_options to list them.");
		}
		OptionType type = opts.getType(name);
		bridge.inTransaction(program, "Set analysis option (MCP)", () -> {
			applyOption(opts, name, type, value);
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("name", name);
		o.addProperty("type", String.valueOf(type));
		o.addProperty("value", String.valueOf(opts.getObject(name, null)));
		return gson.toJson(o);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private void applyOption(Options opts, String name, OptionType type, String value)
			throws ToolException {
		try {
			switch (type) {
				case BOOLEAN_TYPE -> opts.setBoolean(name, parseBool(value));
				case INT_TYPE -> opts.setInt(name, Integer.parseInt(value.trim()));
				case LONG_TYPE -> opts.setLong(name, Long.parseLong(value.trim()));
				case DOUBLE_TYPE -> opts.setDouble(name, Double.parseDouble(value.trim()));
				case FLOAT_TYPE -> opts.setFloat(name, Float.parseFloat(value.trim()));
				case STRING_TYPE -> opts.setString(name, value);
				case ENUM_TYPE -> {
					Object current = opts.getObject(name, null);
					if (!(current instanceof Enum<?> e)) {
						throw new ToolException("Option '" + name + "' is an enum but has no current value.");
					}
					Enum target = Enum.valueOf((Class) e.getClass(), value.trim());
					opts.setEnum(name, target);
				}
				default -> throw new ToolException("Unsupported option type " + type +
					" for '" + name + "'.");
			}
		}
		catch (NumberFormatException nfe) {
			throw new ToolException("Value '" + value + "' is not valid for option type " + type + ".");
		}
		catch (IllegalArgumentException iae) {
			throw new ToolException("Value '" + value + "' is not a valid choice for '" + name + "'.");
		}
	}

	private boolean parseBool(String v) throws ToolException {
		String s = v.trim().toLowerCase();
		if (s.equals("true") || s.equals("1") || s.equals("yes") || s.equals("on")) {
			return true;
		}
		if (s.equals("false") || s.equals("0") || s.equals("no") || s.equals("off")) {
			return false;
		}
		throw new ToolException("Expected a boolean for this option, got '" + v + "'.");
	}

	/** Exposed for potential callers needing the raw option name list. */
	List<String> optionNames(Program program) {
		return program.getOptions(Program.ANALYSIS_PROPERTIES).getOptionNames();
	}
}
