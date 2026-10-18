package ghidrallm.mcp.ops;

import java.io.File;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import ghidra.app.util.exporter.BinaryExporter;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallm.mcp.server.ToolException;

/**
 * Persisting work: save the program back into the Ghidra project, and export the (patched)
 * program bytes to a file on disk. Together with the patch tools these close the
 * patch-a-binary loop.
 */
public class ExportOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public ExportOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String saveProgram(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		DomainFile df = p.getDomainFile();
		if (df == null) {
			throw new ToolException("Program has no associated project file to save.");
		}
		try {
			df.save(TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			throw new ToolException("Could not save '" + p.getName() + "': " + e.getMessage());
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("path", df.getPathname());
		o.addProperty("saved", true);
		return gson.toJson(o);
	}

	public String exportProgram(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String path = GhidraBridge.reqStr(args, "path");
		String format = GhidraBridge.str(args, "format", "binary").toLowerCase();
		if (!format.equals("binary")) {
			throw new ToolException("Only 'binary' export is supported (writes the raw, patched " +
				"bytes of defined memory). Got '" + format + "'.");
		}
		File out = new File(path);
		if (out.getParentFile() != null && !out.getParentFile().isDirectory()) {
			throw new ToolException("Output directory does not exist: " + out.getParent());
		}
		BinaryExporter exporter = new BinaryExporter();
		boolean ok;
		try {
			// null address set => the exporter's default (initialized memory).
			ok = exporter.export(out, p, null, TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			throw new ToolException("Export failed: " + e.getMessage());
		}
		String log = exporter.getMessageLog() == null ? "" : exporter.getMessageLog().toString().trim();
		if (!ok) {
			throw new ToolException("Exporter reported failure." + (log.isEmpty() ? "" : "\n" + log));
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("format", "binary");
		o.addProperty("outputFile", out.getAbsolutePath());
		o.addProperty("bytes", out.length());
		if (!log.isEmpty()) {
			o.addProperty("log", log);
		}
		return gson.toJson(o);
	}
}
