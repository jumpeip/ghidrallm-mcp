# Contributing to GhidraMCP

Thanks for your interest in improving GhidraMCP.

## Building

You need a JDK (21+), Gradle, and a Ghidra 12.1.4 installation.

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC   # Windows: set GHIDRA_INSTALL_DIR=...
gradle buildExtension
```

The installable extension zip is written to `dist/`. Install it via
`File > Install Extensions` in Ghidra, then enable **GhidraMcpPlugin** in a CodeBrowser tool
(`File > Configure… > Miscellaneous`).

## Adding a tool

Tools are plain methods on an `ops/*Ops` class and are registered in
[`ToolCatalog`](src/main/java/ghidrallm/mcp/ops/ToolCatalog.java):

1. Add a handler method `String myTool(JsonObject args)` to the relevant `*Ops` class
   (or a new one). Return a JSON string; throw `ToolException` for expected errors.
2. Register it in `ToolCatalog.build(...)` with a name, description, and JSON schema
   (use the `schema(...)` / `strProp(...)` helpers).
3. Rebuild — `tools/list` is generated from the catalog, so no protocol code changes.

Keep program reads on the worker thread and wrap all modifications in
`bridge.inTransaction(...)` so each edit is individually undoable in Ghidra.

## Conventions

- Match the existing code style (tabs, Javadoc on public methods).
- Prefer the APIs already used in the `ops/` classes; verify any new Ghidra API against the
  12.1.4 source before relying on it.
- The endpoint is localhost-only and unauthenticated by design — don't add features that
  broaden network exposure without a clear opt-in.

## Scope

This project is intended for **authorized** security work — reverse engineering, vulnerability
assessment, CTFs, and research on binaries you are permitted to analyze.
