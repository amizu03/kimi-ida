# KIMI-IDA

**kimi-ida** is a Rust-based plugin for IDA Pro that integrates the Moonshot AI (KIMI) API to provide automated reverse engineering analysis. The plugin decompiles functions using Hex-Rays, sends the pseudocode to the KIMI AI for analysis, and applies the results (renamed variables, comments, function names) back to the IDA database.

### Key Features
- **Single Function Analysis**: Analyze the current function under the cursor (Ctrl+Shift+K)
- **Batch Analysis**: Analyze all functions in the binary automatically
- **Smart Variable Renaming**: AI-suggested meaningful variable names
- **Automatic Commenting**: Adds explanatory comments to complex code sections
- **Function Renaming**: Suggests descriptive function names based on heuristic analysis

## Build Instructions

### Prerequisites

1. **Rust nightly toolchain** (required for unstable features):
```bash
rustup default nightly
rustup target add x86_64-pc-windows-msvc
rustup component add rust-src  # Required for build-std
```

2. **IDA SDK** (automatically cloned as submodule or set via env var):
```bash
git submodule update --init --recursive
```
or
```bash
set IDASDK=path-to-ida-sdk
```

3. **Static Library**:
Ensure `ida.lib` is in the project root for linking

### Build Commands

```bash
# Debug build
cargo build

# Release build (optimized, recommended)
cargo build --release

# The plugin DLL will be at:
target/release/kimi_ida.dll
```

## Installation and Usage

### Deploy to IDA Pro

1. Copy `target/release/kimi_ida.dll` to IDA's plugins directory:
   ```
   C:\Program Files\IDA Pro 9.x\plugins\kimi_ida.dll
   ```

2. Set environment variable before launching IDA:
   ```bash
   set KIMI_API_KEY=sk-kimi-your-api-key-here
   ```

### Using the Plugin

- **Analyze Current Function**: Press `Ctrl+Shift+K` in pseudocode view, or right-click → "KIMI: Analyze function"
- **Analyze All Functions**: Right-click in pseudocode view → "KIMI: Analyze all functions"
- **View Output**: Check IDA's Output window for `[KIMI]` prefixed messages

## License

MIT License - See `LICENSE` file for details.

Copyright (c) 2026 Alex Mizumori
