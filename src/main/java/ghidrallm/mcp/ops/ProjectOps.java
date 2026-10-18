package ghidrallm.mcp.ops;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidrallm.mcp.server.ToolException;

/**
 * Project lifecycle: open an existing program from the project, close an open program, and
 * list the program files the project contains.
 */
public class ProjectOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public ProjectOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	private ProjectData projectData() throws ToolException {
		Project project = bridge.tool().getProject();
		if (project == null) {
			throw new ToolException("No active Ghidra project.");
		}
		return project.getProjectData();
	}

	public String listProjectFiles(JsonObject args) throws ToolException {
		ProjectData pd = projectData();
		JsonArray arr = new JsonArray();
		collect(pd.getRootFolder(), arr);
		JsonObject o = new JsonObject();
		o.addProperty("count", arr.size());
		o.add("files", arr);
		return gson.toJson(o);
	}

	private void collect(DomainFolder folder, JsonArray arr) {
		for (DomainFile f : folder.getFiles()) {
			JsonObject o = new JsonObject();
			o.addProperty("name", f.getName());
			o.addProperty("path", f.getPathname());
			o.addProperty("contentType", f.getContentType());
			arr.add(o);
		}
		for (DomainFolder sub : folder.getFolders()) {
			collect(sub, arr);
		}
	}

	public String openProgram(JsonObject args) throws Exception {
		String path = GhidraBridge.reqStr(args, "path");
		ProjectData pd = projectData();
		DomainFile df = pd.getFile(path);
		if (df == null) {
			throw new ToolException("No project file at '" + path +
				"'. Call list_project_files to see available paths.");
		}
		ProgramManager pm = bridge.programManager();
		if (pm == null) {
			throw new ToolException("This tool has no ProgramManager service to open programs.");
		}
		Program opened = bridge.onSwing(() -> pm.openProgram(df));
		if (opened == null) {
			throw new ToolException("Could not open '" + path + "' (not a program, or failed to open).");
		}
		JsonObject o = new JsonObject();
		o.addProperty("name", opened.getName());
		o.addProperty("path", df.getPathname());
		o.addProperty("languageId", opened.getLanguageID().getIdAsString());
		o.addProperty("functionCount", opened.getFunctionManager().getFunctionCount());
		return gson.toJson(o);
	}

	public String closeProgram(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		boolean force = GhidraBridge.boolArg(args, "force", false);
		ProgramManager pm = bridge.programManager();
		if (pm == null) {
			throw new ToolException("This tool has no ProgramManager service.");
		}
		String name = p.getName();
		boolean closed = bridge.onSwing(() -> pm.closeProgram(p, force));
		JsonObject o = new JsonObject();
		o.addProperty("program", name);
		o.addProperty("closed", closed);
		if (!closed) {
			o.addProperty("note", "Not closed - it may have unsaved changes. Save first, or pass force=true.");
		}
		return gson.toJson(o);
	}
}
