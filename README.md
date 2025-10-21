# ida-xed

An experimental **IDA Pro** plugin that integrates the **Intel XED** decoder to enrich x86/x64 instruction analysis inside IDA, since sometimes IDA can't handle certain opcodes - [example](https://github.com/sapdragon/hint-break)


---

## Features

* Decode the instruction at the current cursor using XED and display a detail pane


> If you have a feature request, please open an issue or PR.

---

## Requirements

* **IDA Pro** 9.0+ (tested on IDA 9.2)
* **Intel XED** (built static or shared)
* **CMake** ≥ 3.20
* **C++17** toolchain (MSVC)
* **IDA SDK** matching your IDA version

> Windows, Linux, and macOS should work if the IDA SDK & XED are available for your platform.

---

## Build

1. **Fetch the sources**

```bash
git clone https://github.com/forentfraps/ida-xed.git
cd ida-xed
```

2. **Build Intel XED** (if you don’t already have it)

* Follow the official XED build instructions to produce a library + headers.
* Note the install prefix (e.g., `XED_ROOT` or `XED_INSTALL_DIR`).

3. **Point CMake at the IDA SDK & XED**

You can pass paths as cache variables or environment variables:

```bash
cmake -S . -B build \
  -DIDA_SDK_DIR="/path/to/idasdk" \
  -DXED_ROOT_DIR="/path/to/xed/install" \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

This should produce a plugin binary (e.g., `ida-xed.plx`/`ida-xed.dylib`/`ida-xed.dll`) under `build/`.

> Tip (Windows + IDA 64‑bit): pick the generator that matches your VS installation, e.g. `-G "Visual Studio 17 2022" -A x64`.

---

## Install

1. Close IDA.
2. Copy the built plugin to your IDA **plugins** directory:

   * **Windows**: `%ProgramFiles%\IDA Pro\plugins\`
   * **Linux**: `~/.idapro/plugins/` or `<IDA>/plugins/`
   * **macOS**: `~/Library/Application Support/Hex-Rays/IDA/plugins/` or `<IDA>.app/Contents/MacOS/plugins/`
3. Start IDA.

---

## Usage

* Open a database and position the cursor on an instruction.
* Invoke via **Edit → Plugins → ida‑xed** (or the hotkey if configured `Alt + X` by default).
* It will disassemble using xed.
