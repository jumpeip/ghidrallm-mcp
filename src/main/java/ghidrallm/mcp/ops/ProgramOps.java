package ghidrallm.mcp.ops;

import java.io.File;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import ghidrallm.mcp.server.ToolException;

/**
 * Program/project level tools: list open programs, current program, import a binary from disk,
 * program metadata and the memory map.
 */
public class ProgramOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public ProgramOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String listOpenPrograms(JsonObject args) {
		JsonArray arr = new JsonArray();
		Program currentProgram = bridge.current();
		for (Program p : bridge.openPrograms()) {
			JsonObject o = new JsonObject();
			o.addProperty("name", p.getName());
			try {
				DomainFile df = p.getDomainFile();
				o.addProperty("path", df == null ? null : df.getPathname());
			}
			catch (Exception ignore) {
				// ignore
			}
			o.addProperty("current", p == currentProgram);
			o.addProperty("functionCount", p.getFunctionManager().getFunctionCount());
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("count", arr.size());
		o.add("programs", arr);
		return gson.toJson(o);
	}

	public String getCurrentProgram(JsonObject args) throws ToolException {
		Program p = bridge.current();
		if (p == null) {
			JsonObject o = new JsonObject();
			o.add("program", null);
			o.addProperty("message", "No program is currently active in Ghidra.");
			return gson.toJson(o);
		}
		return describe(p);
	}

	public String programInfo(JsonObject args) throws ToolException {
		Program p = bridge.resolve(args);
		return describe(p);
	}

	private String describe(Program p) {
		JsonObject o = new JsonObject();
		o.addProperty("name", p.getName());
		try {
			DomainFile df = p.getDomainFile();
			o.addProperty("path", df == null ? null : df.getPathname());
		}
		catch (Exception ignore) {
			// ignore
		}
		o.addProperty("executableFormat", p.getExecutableFormat());
		o.addProperty("executablePath", p.getExecutablePath());
		o.addProperty("executableMD5", p.getExecutableMD5());
		o.addProperty("executableSHA256", p.getExecutableSHA256());
		o.addProperty("languageId", p.getLanguageID().getIdAsString());
		o.addProperty("compilerSpecId", p.getCompilerSpec().getCompilerSpecID().getIdAsString());
		o.addProperty("processor", p.getLanguage().getProcessor().toString());
		o.addProperty("endian", p.getLanguage().isBigEndian() ? "big" : "little");
		o.addProperty("pointerSize", p.getDefaultPointerSize());
		o.addProperty("imageBase", p.getImageBase().toString());
		o.addProperty("minAddress", String.valueOf(p.getMinAddress()));
		o.addProperty("maxAddress", String.valueOf(p.getMaxAddress()));
		o.addProperty("functionCount", p.getFunctionManager().getFunctionCount());
		o.addProperty("symbolCount", p.getSymbolTable().getNumSymbols());
		return gson.toJson(o);
	}

	public String listMemoryBlocks(JsonObject args) throws ToolException {
		Program p = bridge.resolve(args);
		JsonArray arr = new JsonArray();
		for (MemoryBlock b : p.getMemory().getBlocks()) {
			JsonObject o = new JsonObject();
			o.addProperty("name", b.getName());
			o.addProperty("start", b.getStart().toString());
			o.addProperty("end", b.getEnd().toString());
			o.addProperty("size", b.getSize());
			StringBuilder perms = new StringBuilder();
			perms.append(b.isRead() ? "r" : "-");
			perms.append(b.isWrite() ? "w" : "-");
			perms.append(b.isExecute() ? "x" : "-");
			o.addProperty("permissions", perms.toString());
			o.addProperty("initialized", b.isInitialized());
			o.addProperty("overlay", b.isOverlay());
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("count", arr.size());
		o.add("blocks", arr);
		return gson.toJson(o);
	}

	public String importBinary(JsonObject args) throws Exception {
		String path = GhidraBridge.reqStr(args, "path");
		boolean analyze = GhidraBridge.boolArg(args, "analyze", true);
		String folderPath = GhidraBridge.str(args, "folder", "/");

		File file = new File(path);
		if (!file.isFile()) {
			throw new ToolException("File not found or not a regular file: " + path);
		}
		Project project = bridge.tool().getProject();
		if (project == null) {
			throw new ToolException("No active Ghidra project. Create or open a project in Ghidra first.");
		}
		ProgramManager pm = bridge.programManager();
		if (pm == null) {
			throw new ToolException("This tool has no ProgramManager service. Add GhidraMCP to the " +
				"CodeBrowser tool (it needs a tool that can open programs).");
		}

		MessageLog log = new MessageLog();
		Program program;
		DomainFile savedFile;

		// load() creates the program with a built-in consumer that close() releases; we grab the
		// primary with our own consumer so it survives after the try-with-resources, then hand it
		// to the ProgramManager (which adds its own consumer) and drop ours.
		Object consumer = this;
		try (LoadResults<Program> results = ProgramLoader.builder()
				.source(file)
				.project(project)
				.projectFolderPath(folderPath)
				.log(log)
				.monitor(TaskMonitor.DUMMY)
				.load()) {
			results.save(TaskMonitor.DUMMY);
			savedFile = results.getPrimary().getSavedDomainFile();
			program = results.getPrimaryDomainObject(consumer);
		}
		catch (Exception e) {
			String detail = log.toString().isBlank() ? "" : ("\n" + log.toString().trim());
			throw new ToolException("Import failed for " + path + ": " + e.getMessage() + detail);
		}

		String analysisNote = "";
		try {
			final Program prog = program;
			bridge.onSwing(() -> {
				pm.openProgram(prog);
				return null;
			});
			if (analyze) {
				analysisNote = AnalysisOps.runAnalysis(bridge, program);
			}
		}
		finally {
			program.release(consumer);
		}

		JsonObject o = new JsonObject();
		o.addProperty("name", program.getName());
		o.addProperty("programFile", savedFile == null ? program.getName() : savedFile.getPathname());
		o.addProperty("languageId", program.getLanguageID().getIdAsString());
		o.addProperty("compilerSpecId", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
		o.addProperty("imageBase", program.getImageBase().toString());
		o.addProperty("functionCount", program.getFunctionManager().getFunctionCount());
		o.addProperty("analyzed", analyze);
		if (!analysisNote.isBlank()) {
			o.addProperty("analysis", analysisNote);
		}
		if (!log.toString().isBlank()) {
			o.addProperty("importLog", log.toString().trim());
		}
		return gson.toJson(o);
	}
}
