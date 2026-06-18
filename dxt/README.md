# 📦 Bridge MCP — DXT Package

## 🤔 What Is DXT?

**DXT (Desktop Extension)** is Claude Desktop's one-click install format for MCP servers. A `.dxt` file is a ZIP archive containing a binary, a manifest, and an icon that Claude Desktop can install directly — no manual configuration needed.

When a user opens a `.dxt` file, Claude Desktop automatically:

1. Extracts the binary to its extensions directory
2. Reads the manifest to register the MCP server
3. Makes all tools available immediately via stdio transport

---

## 📄 manifest.json Structure

The `manifest.json` file describes the extension to Claude Desktop:

```json
{
  "dxt_version": "0.1",
  "name": "bridge-mcp",
  "display_name": "Bridge MCP",
  "version": "1.4.0",
  "description": "Execute commands securely on remote servers via SSH. 337 tools for Linux, Windows, Docker, Kubernetes, and more.",
  "author": {
    "name": "muchini"
  },
  "mcp": {
    "command": {
      "type": "binary",
      "path": "bridge-mcp"
    },
    "transport": "stdio"
  },
  "platforms": ["linux-x64", "linux-arm64", "macos-x64", "macos-arm64", "windows-x64"],
  "icon": "icon.svg"
}
```

### 🔑 Key Fields

| Field | Description |
|-------|-------------|
| `dxt_version` | DXT specification version (currently `"0.1"`) |
| `name` | Package identifier (used for installation path) |
| `display_name` | Human-readable name shown in Claude Desktop UI |
| `version` | Semver version of the extension |
| `description` | Short description shown during install and in settings |
| `author.name` | Author name |
| `mcp.command.type` | `"binary"` indicates a compiled executable |
| `mcp.command.path` | Path to the binary relative to the package root |
| `mcp.transport` | MCP transport protocol (`"stdio"` for stdin/stdout JSON-RPC) |
| `platforms` | List of supported platform targets |
| `icon` | Path to the extension icon (SVG format) |

---

## 🔨 How to Build

Build the DXT package using the Makefile:

```bash
make dxt
```

This runs the following steps:

1. Builds an optimized release binary (`make release`)
2. Creates `dist/dxt/` directory
3. Copies the release binary, `manifest.json`, and `icon.svg` into it
4. Zips the directory into `dist/bridge-mcp.dxt`

The output package is at:

```
dist/bridge-mcp.dxt
```

---

## 🖥️ How to Install in Claude Desktop

1. **Build the package:**

   ```bash
   make dxt
   ```

2. **Open the `.dxt` file** in Claude Desktop:
   - Double-click `dist/bridge-mcp.dxt`, or
   - Drag and drop it into the Claude Desktop window, or
   - Use Claude Desktop's extension installer: **Settings → Extensions → Install from file**

3. **Configure your SSH hosts** in `~/.config/bridge-mcp/config.yaml` (see `config/config.example.yaml` for the full schema)

4. **Start using SSH tools** — all 337 tools are now available in Claude Desktop conversations

---

## 📁 What's Included in the Package

The `.dxt` archive contains:

```
dxt/
├── bridge-mcp          # Compiled release binary (with LTO optimization)
├── manifest.json           # DXT manifest describing the extension
└── icon.svg                # Extension icon displayed in Claude Desktop
```

| File | Source | Purpose |
|------|--------|---------|
| `bridge-mcp` | `target/release/bridge-mcp` | The MCP server binary |
| `manifest.json` | `dxt/manifest.json` | Extension metadata and MCP configuration |
| `icon.svg` | `dxt/icon.svg` | Visual identity in Claude Desktop UI |

---

## 🏗️ Supported Platforms

| Platform | Architecture |
|----------|-------------|
| Linux | x86_64, ARM64 |
| macOS | x86_64 (Intel), ARM64 (Apple Silicon) |
| Windows | x86_64 |

> **Note:** The `make dxt` command builds for the current host platform. To produce packages for other platforms, cross-compile the binary first (e.g., using `make release-target TARGET=aarch64-unknown-linux-gnu`) and then assemble the DXT package manually.
