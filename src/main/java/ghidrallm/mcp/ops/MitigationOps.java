package ghidrallm.mcp.ops;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.task.TaskMonitor;
import ghidrallm.mcp.server.ToolException;

/**
 * Binary hardening and crypto fingerprinting: report exploit-mitigation flags (NX, ASLR, CFG,
 * SEH, stack canary) for PE/ELF, and scan memory for well-known crypto constant tables.
 */
public class MitigationOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public MitigationOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	// ------------------------------------------------------------ mitigations

	public String checkSecurityMitigations(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String format = p.getExecutableFormat();
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("format", format);

		byte[] hdr = readUpTo(p.getMemory(), p.getImageBase(), 0x1000);
		if (format != null && format.toLowerCase().contains("portable executable") && hdr != null) {
			parsePe(hdr, o);
		}
		else if (format != null && format.toLowerCase().contains("elf") && hdr != null) {
			parseElf(hdr, o);
		}
		else {
			o.addProperty("note", "Header-based mitigation parsing supports PE and ELF; " +
				"reporting symbol-based hints only.");
		}
		o.addProperty("stackCanary", hasAnySymbol(p, "__security_cookie", "__stack_chk_fail",
			"__stack_chk_guard", "__security_check_cookie"));
		return gson.toJson(o);
	}

	private void parsePe(byte[] b, JsonObject o) {
		int e_lfanew = le32(b, 0x3C);
		if (e_lfanew <= 0 || e_lfanew + 0x60 > b.length
			|| b[e_lfanew] != 'P' || b[e_lfanew + 1] != 'E') {
			o.addProperty("note", "Could not locate PE header in mapped image.");
			return;
		}
		int coff = e_lfanew + 4;
		int characteristics = le16(b, coff + 18);
		int opt = coff + 20;
		int magic = le16(b, opt);
		o.addProperty("peType", magic == 0x20b ? "PE32+" : "PE32");
		int dllc = le16(b, opt + 0x46);
		boolean relocsStripped = (characteristics & 0x0001) != 0;
		boolean dynamicBase = (dllc & 0x0040) != 0;
		o.addProperty("aslr", dynamicBase && !relocsStripped);
		o.addProperty("highEntropyVA", (dllc & 0x0020) != 0);
		o.addProperty("dep_nx", (dllc & 0x0100) != 0);
		o.addProperty("cfg", (dllc & 0x4000) != 0);
		o.addProperty("seh", (dllc & 0x0400) == 0); // NO_SEH bit clear => SEH present
		o.addProperty("forceIntegrity", (dllc & 0x0080) != 0);
		o.addProperty("relocationsStripped", relocsStripped);
		o.addProperty("dllCharacteristics", String.format("0x%04x", dllc));
	}

	private void parseElf(byte[] b, JsonObject o) {
		boolean is64 = b[4] == 2;
		boolean be = b[5] == 2;
		o.addProperty("elfClass", is64 ? "ELF64" : "ELF32");
		int e_type = u16(b, 16, be);
		o.addProperty("pie", e_type == 3); // ET_DYN
		long e_phoff = is64 ? u64(b, 32, be) : u32(b, 28, be);
		int e_phentsize = u16(b, is64 ? 54 : 42, be);
		int e_phnum = u16(b, is64 ? 56 : 44, be);
		boolean nx = true; // default: no exec stack unless GNU_STACK says otherwise
		boolean sawGnuStack = false;
		boolean relro = false;
		for (int i = 0; i < e_phnum; i++) {
			long off = e_phoff + (long) i * e_phentsize;
			if (off + e_phentsize > b.length) {
				break;
			}
			int type = (int) u32(b, (int) off, be);
			if (type == 0x6474e551) { // PT_GNU_STACK
				sawGnuStack = true;
				int flags = is64 ? (int) u32(b, (int) off + 4, be) : (int) u32(b, (int) off + 24, be);
				nx = (flags & 0x1) == 0; // X bit set => executable stack => NX off
			}
			else if (type == 0x6474e552) { // PT_GNU_RELRO
				relro = true;
			}
		}
		o.addProperty("nx", sawGnuStack ? nx : false);
		o.addProperty("nxNote", sawGnuStack ? "from PT_GNU_STACK" : "no PT_GNU_STACK (exec stack likely)");
		o.addProperty("relro", relro);
		o.addProperty("relroNote", relro ? "PT_GNU_RELRO present (partial or full)" : "no PT_GNU_RELRO");
	}

	// ------------------------------------------------------------ crypto constants

	public String findCryptoConstants(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		int perSig = clamp(GhidraBridge.intArg(args, "max_per_signature", 3), 50);
		Memory mem = p.getMemory();
		Map<String, byte[]> sigs = signatures();
		JsonArray arr = new JsonArray();
		for (Map.Entry<String, byte[]> e : sigs.entrySet()) {
			Address cur = p.getMinAddress();
			int found = 0;
			while (cur != null && found < perSig) {
				Address at = mem.findBytes(cur, e.getValue(), null, true, TaskMonitor.DUMMY);
				if (at == null) {
					break;
				}
				JsonObject o = new JsonObject();
				o.addProperty("signature", e.getKey());
				o.addProperty("address", at.toString());
				arr.add(o);
				found++;
				try {
					cur = at.add(1);
				}
				catch (Exception ex) {
					break;
				}
			}
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("signaturesChecked", sigs.size());
		o.addProperty("matchCount", arr.size());
		o.add("matches", arr);
		return gson.toJson(o);
	}

	private Map<String, byte[]> signatures() {
		Map<String, byte[]> m = new LinkedHashMap<>();
		m.put("AES_SBOX", hex("637c777bf26b6fc53001672bfed7ab76"));
		m.put("AES_INV_SBOX", hex("52096ad53036a538bf40a39e81f3d7fb"));
		m.put("SHA256_INIT_BE", hex("6a09e667bb67ae85"));
		m.put("SHA256_INIT_LE", hex("67e6096a85ae67bb"));
		m.put("SHA1_INIT_BE", hex("67452301efcdab89"));
		m.put("MD5_INIT_LE", hex("0123456789abcdeffedcba9876543210"));
		m.put("MT19937_MATRIX_A_LE", hex("dfb00899"));
		m.put("BASE64_STD_ALPHABET",
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
				.getBytes(StandardCharsets.US_ASCII));
		return m;
	}

	// ------------------------------------------------------------ helpers

	private boolean hasAnySymbol(Program p, String... names) {
		for (String n : names) {
			SymbolIterator it = p.getSymbolTable().getSymbols(n);
			if (it.hasNext()) {
				return true;
			}
		}
		return false;
	}

	private static byte[] readUpTo(Memory mem, Address addr, int max) {
		int[] sizes = { max, 0x800, 0x400, 0x200, 0x100, 0x40 };
		for (int size : sizes) {
			if (size > max) {
				continue;
			}
			byte[] buf = new byte[size];
			try {
				int read = mem.getBytes(addr, buf);
				if (read == size) {
					return buf;
				}
				if (read > 0) {
					byte[] out = new byte[read];
					System.arraycopy(buf, 0, out, 0, read);
					return out;
				}
			}
			catch (Exception ignore) {
				// try a smaller read
			}
		}
		return null;
	}

	private static int le16(byte[] b, int off) {
		return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
	}

	private static int le32(byte[] b, int off) {
		return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
			| ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
	}

	private static int u16(byte[] b, int off, boolean be) {
		int a = b[off] & 0xff;
		int c = b[off + 1] & 0xff;
		return be ? (a << 8) | c : (c << 8) | a;
	}

	private static long u32(byte[] b, int off, boolean be) {
		long a = b[off] & 0xffL, c = b[off + 1] & 0xffL, d = b[off + 2] & 0xffL, e = b[off + 3] & 0xffL;
		return be ? (a << 24) | (c << 16) | (d << 8) | e : (e << 24) | (d << 16) | (c << 8) | a;
	}

	private static long u64(byte[] b, int off, boolean be) {
		long lo, hi;
		if (be) {
			hi = u32(b, off, true);
			lo = u32(b, off + 4, true);
		}
		else {
			lo = u32(b, off, false);
			hi = u32(b, off + 4, false);
		}
		return (hi << 32) | (lo & 0xffffffffL);
	}

	private static byte[] hex(String s) {
		byte[] out = new byte[s.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
	}

	private static int clamp(int v, int max) {
		return (v <= 0 || v > max) ? max : v;
	}
}
