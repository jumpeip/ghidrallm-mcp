package ghidrallm.mcp.ops;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import ghidrallm.mcp.server.ToolException;

/**
 * Create memory blocks (e.g. to map additional data or scratch regions) and change block
 * read/write/execute permissions.
 */
public class MemoryBlockOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public MemoryBlockOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String createMemoryBlock(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String name = GhidraBridge.reqStr(args, "name");
		Address start = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		long size = readLong(args, "size");
		if (size <= 0) {
			throw new ToolException("'size' must be a positive number of bytes.");
		}
		byte fill = (byte) GhidraBridge.longFromStr(GhidraBridge.str(args, "fill", "0"));
		boolean overlay = GhidraBridge.boolArg(args, "overlay", false);
		Memory mem = p.getMemory();

		MemoryBlock block = bridge.inTransaction(p, "Create memory block (MCP)", () -> {
			try {
				return mem.createInitializedBlock(name, start, size, fill, TaskMonitor.DUMMY, overlay);
			}
			catch (Exception e) {
				throw new ToolException("Could not create block '" + name + "' at " + start +
					" (size " + size + "): " + e.getMessage());
			}
		});

		JsonObject o = new JsonObject();
		o.addProperty("name", block.getName());
		o.addProperty("start", block.getStart().toString());
		o.addProperty("end", block.getEnd().toString());
		o.addProperty("size", block.getSize());
		o.addProperty("overlay", block.isOverlay());
		return gson.toJson(o);
	}

	public String setMemoryPermissions(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Memory mem = p.getMemory();
		MemoryBlock block;
		String blockName = GhidraBridge.str(args, "block", null);
		if (blockName != null && !blockName.isBlank()) {
			block = mem.getBlock(blockName);
			if (block == null) {
				throw new ToolException("No memory block named '" + blockName + "'.");
			}
		}
		else {
			Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
			block = mem.getBlock(addr);
			if (block == null) {
				throw new ToolException("No memory block contains " + addr + ".");
			}
		}
		final MemoryBlock b = block;
		bridge.inTransaction(p, "Set block permissions (MCP)", () -> {
			if (args.has("read")) {
				b.setRead(GhidraBridge.boolArg(args, "read", true));
			}
			if (args.has("write")) {
				b.setWrite(GhidraBridge.boolArg(args, "write", false));
			}
			if (args.has("execute")) {
				b.setExecute(GhidraBridge.boolArg(args, "execute", false));
			}
			return null;
		});
		StringBuilder perms = new StringBuilder();
		perms.append(b.isRead() ? "r" : "-");
		perms.append(b.isWrite() ? "w" : "-");
		perms.append(b.isExecute() ? "x" : "-");
		JsonObject o = new JsonObject();
		o.addProperty("block", b.getName());
		o.addProperty("permissions", perms.toString());
		return gson.toJson(o);
	}

	private static long readLong(JsonObject args, String key) throws ToolException {
		if (!args.has(key) || args.get(key).isJsonNull()) {
			throw new ToolException("Missing required argument '" + key + "'.");
		}
		JsonElement e = args.get(key);
		if (e.isJsonPrimitive() && e.getAsJsonPrimitive().isString()) {
			return GhidraBridge.longFromStr(e.getAsString());
		}
		return e.getAsLong();
	}
}
