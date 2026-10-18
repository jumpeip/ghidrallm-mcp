package ghidrallm.mcp.ops;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import ghidrallm.mcp.server.ToolException;

/**
 * Memory search: byte patterns (with {@code ??} wildcards) and literal strings.
 */
public class SearchOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public SearchOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String searchBytes(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String pattern = GhidraBridge.reqStr(args, "pattern");
		int limit = clampLimit(GhidraBridge.intArg(args, "limit", 100));
		Address start = startAddress(p, args);

		byte[][] bm = parsePattern(pattern);
		return runSearch(p, bm[0], bm[1], start, limit, "pattern", pattern);
	}

	public String searchString(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String text = GhidraBridge.reqStr(args, "text");
		int limit = clampLimit(GhidraBridge.intArg(args, "limit", 100));
		Address start = startAddress(p, args);
		String encoding = GhidraBridge.str(args, "encoding", "ascii").toLowerCase();

		Charset cs = switch (encoding) {
			case "ascii" -> StandardCharsets.US_ASCII;
			case "utf8", "utf-8" -> StandardCharsets.UTF_8;
			case "utf16le", "utf-16le" -> StandardCharsets.UTF_16LE;
			case "utf16be", "utf-16be" -> StandardCharsets.UTF_16BE;
			default -> throw new ToolException("Unknown encoding '" + encoding +
				"'. Use ascii, utf8, utf16le or utf16be.");
		};
		byte[] bytes = text.getBytes(cs);
		return runSearch(p, bytes, null, start, limit, "text", text);
	}

	// ------------------------------------------------------------ core

	private String runSearch(Program p, byte[] bytes, byte[] masks, Address start, int limit,
			String queryKey, String queryValue) throws Exception {
		Memory mem = p.getMemory();
		JsonArray hits = new JsonArray();
		Address cur = start;
		while (cur != null && hits.size() < limit) {
			Address found = mem.findBytes(cur, bytes, masks, true, TaskMonitor.DUMMY);
			if (found == null) {
				break;
			}
			JsonObject o = new JsonObject();
			o.addProperty("address", found.toString());
			Function fn = p.getFunctionManager().getFunctionContaining(found);
			if (fn != null) {
				o.addProperty("function", fn.getName());
			}
			hits.add(o);
			try {
				cur = found.add(1);
			}
			catch (Exception e) {
				break; // ran off the end of the address space
			}
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty(queryKey, queryValue);
		o.addProperty("length", bytes.length);
		o.addProperty("count", hits.size());
		o.add("matches", hits);
		return gson.toJson(o);
	}

	private Address startAddress(Program p, JsonObject args) throws ToolException {
		String s = GhidraBridge.str(args, "start", null);
		if (s != null && !s.isBlank()) {
			return bridge.address(p, s);
		}
		return p.getMinAddress();
	}

	/** Returns [bytes, masks]; masks[i]=0xFF for a fixed byte, 0x00 for a {@code ??} wildcard. */
	private byte[][] parsePattern(String pattern) throws ToolException {
		String clean = pattern.replaceAll("[\\s,]", "").replaceAll("(?i)^0x", "");
		if (clean.isEmpty() || clean.length() % 2 != 0) {
			throw new ToolException("Byte pattern must be pairs of hex digits or '??', e.g. '8b ?? 90'.");
		}
		int n = clean.length() / 2;
		byte[] bytes = new byte[n];
		byte[] masks = new byte[n];
		for (int i = 0; i < n; i++) {
			String pair = clean.substring(i * 2, i * 2 + 2);
			if (pair.equals("??")) {
				bytes[i] = 0;
				masks[i] = 0;
			}
			else {
				try {
					bytes[i] = (byte) Integer.parseInt(pair, 16);
					masks[i] = (byte) 0xFF;
				}
				catch (NumberFormatException e) {
					throw new ToolException("Invalid byte '" + pair + "' in pattern.");
				}
			}
		}
		return new byte[][] { bytes, masks };
	}

	private static int clampLimit(int limit) {
		return (limit <= 0 || limit > 5000) ? 5000 : limit;
	}
}
