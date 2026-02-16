# iOS IPA Frida Gadget Injector

This script helps with injecting **Frida Gadget** into an iOS `.ipa` file:

- Copies `FridaGadget.dylib` into the app bundle
- Adds an `LC_LOAD_DYLIB` load command to the main executable (`@executable_path/<dylib>`)
- Optionally embeds a Frida Gadget `.config`
- Repackages the `.ipa`

It does **not** require macOS. You can run it on Linux/WSL (and the included GitHub Actions workflow uses `ubuntu-latest`).

## Screenshot

![Example script run](https://i.imgur.com/25vdYFc.png)

## Prerequisites

### Local (Linux / WSL)

- Python 3
- `lief` (Python package)

Install:

```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

### Local (macOS)

- Python 3
- `lief`
- Optional: `ldid` (only for best-effort ad-hoc signing; not a substitute for real iOS signing)

Install:

```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt

brew install ldid  # optional
```

### Device / USB Tools (for attaching from a computer)

To forward a Gadget TCP port over USB you typically use `iproxy` (libimobiledevice):

- Linux: `sudo apt-get install -y libimobiledevice-utils`
- macOS: `brew install libimobiledevice`
- Windows: download `iproxy` from:
  - `https://github.com/libimobiledevice-win32/imobiledevice-net/releases`

## Inject Frida Gadget

Basic injection using a custom frida gadget version on jailed iOS:

```bash
python inject_frida_dylib.py \
  -i DVIA-v2.ipa \
  -g 17.7.1 \
  --generate-config resume \
  --code-signing required \
  -o DVIA-v2.frida.ipa
```

### Script Arguments

`inject_frida_dylib.py` supports the following options:

| Option | Required | Meaning |
|---|---:|---|
| `-h`, `--help` | No | Show help and exit. |
| `-i`, `--ipa IPA` | Yes | Input IPA path. |
| `-g`, `--gadget GADGET` | Yes | Gadget source: local path, URL to a release asset, `latest`, or a version like `17.7.1`. |
| `-o`, `--out OUT` | No | Output IPA path. Default is `<input>.frida.ipa`. |
| `--dylib-name NAME` | No | Filename to use for the embedded gadget inside the `.app`. Default `FridaGadget.dylib`. |
| `--load-path PATH` | No | Mach-O `LC_LOAD_DYLIB` path to inject. Default is `@executable_path/<embedded-dylib-name>`. |
| `--keep-downloaded-name` | No | If `-g` downloads the gadget, keep the original downloaded filename inside the `.app` instead of renaming to `--dylib-name`. |
| `--gadget-config PATH` | No | Embed a provided Gadget config JSON file next to the dylib (named to match the dylib, with `.config` extension). |
| `--generate-config {resume,wait}` | No | Generate and embed a Gadget config. If omitted, no config is generated. |
| `--listen-address ADDR` | No | Address to bind in generated config. Default `127.0.0.1`. Only used with `--generate-config`. |
| `--listen-port PORT` | No | Port to bind in generated config. Default `27042`. Only used with `--generate-config`. |
| `--on-port-conflict {fail,pick}` | No | Behavior if port is in use in generated config. Default `fail`. Only used with `--generate-config`. |
| `--code-signing {optional,required}` | No | Adds `"code_signing"` to the generated config. Only used with `--generate-config`. |
| `--no-sign` | No | Skip the script’s best-effort `ldid` signing pass (if `ldid` is installed). |

Notes:

- `--generate-config resume` prevents “app opens then closes” caused by Gadget waiting for an attach at startup.
- The script needs Python `lief` to patch Mach-O load commands.
- On jailed iOS, you will still need a real re-sign step for installation (AltStore/Sideloadly/SideStore/LiveContainer/Xcode signing, etc.).

### `--code-signing` vs `--no-sign`

These two flags are unrelated and affect different things:

- `--code-signing {optional,required}`:
  - Adds a **Frida Gadget config** entry (`"code_signing": "optional|required"`) to the generated `FridaGadget.config`.
  - This is a **Gadget runtime mode**, not an iOS signing step.
  - Only applies when you use `--generate-config ...`.
  - Read more at [frida.re](https://frida.re/docs/gadget/#:~:text=JavaScript%20runtime%20used.-,code_signing,-%3A%20string%20specifying%20either)

- `--no-sign`:
  - Skips the script's **best-effort `ldid` signing** pass over Mach-O files in the `.app`.
  - This does not replace proper iOS signing; it's just an optional local step.


### Important:

- `code_signing: required` is a **Frida Gadget mode** used for jailed iOS compatibility.
- This mode restricts Interceptor API for iOS
- On jailed iOS with `code_signing: required`, many Objection features may not work.

### Avoid Port Conflicts (Multiple Gadget Apps)

If you have more than one app with Gadget installed, use a unique port per app:

```bash
python inject_frida_dylib.py \
  -i DVIA-v2.ipa \
  -g frida-gadget-17.7.1-ios-universal.dylib \
  --generate-config resume \
  --code-signing required \
  --listen-port 27044 \
  -o DVIA-port27044.ipa
```

### Download Gadget Automatically

Downloads latest Frida Gadget from the official `frida/frida` GitHub releases:

```bash
python inject_frida_dylib.py \
  -i DVIA-v2.ipa \
  -g latest \
  --generate-config resume \
  --code-signing required \
  -o DVIA-latest.ipa
```

Or a specific version:

```bash
python inject_frida_dylib.py \
  -i DVIA-v2.ipa \
  -g 17.6.2 \
  --generate-config resume \
  --code-signing required \
  -o DVIA-17.6.2.ipa
```

Or use local 

```bash
python inject_frida_dylib.py \
  -i DVIA-v2.ipa \
  -g frida-gadget-17.7.1-ios-universal.dylib \
  --generate-config resume \
  --code-signing required \
  -o DVIA-17.6.2.ipa
```

## Attach To The App (Frida / Objection)

### USB Attach (Recommended)

1. Forward the Gadget port:

```bash
.\iproxy.exe 27042 27042
```

2. Launch the app on the iPhone.

3. Attach using Frida:

```bash
frida-ps -H 127.0.0.1:27042 -a
frida -H 127.0.0.1:27042 -n Gadget
```

### Objection (Gadget Endpoint)

Objection attaches to the Gadget endpoint using `-n Gadget` and network mode:

```bash
objection -N -h 127.0.0.1 -P 27042 -n Gadget start
```

### Verify Frida is Working

When connected, verify the main module path:

```js
Process.id
Process.name
Process.arch
Process.platform
Process.enumerateModules()[0]

ObjC.available
ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString()
ObjC.classes.NSBundle.mainBundle().bundlePath().toString()
```

You should see the app’s executable (example: `DVIA-v2`) and a path like:

`/private/var/containers/Bundle/Application/<UUID>/...app/<Executable>`


## Troubleshooting

### App Opens Then Closes Immediately

Common fixes:

- Use `--generate-config resume` (so Gadget doesn’t block startup)
- For jailed iOS, try `--code-signing required`
- Re-sign the output IPA properly for your install method

### `ObjC.available` Drops Connection

Usually the target process crashed or there is a Frida host/Gadget mismatch.
Match versions and pull device logs:

```bash
idevicesyslog | egrep -i 'DVIA|Gadget|frida|amfid|dyld|jetsam|watchdog|killed|terminated|exception'
```

## GitHub Actions

You can fork this repo and run GitHub Actions to produce a patched IPA automatically.

1. Fork the repo
2. Go to the **Actions** tab in your fork
3. Run the workflow **Patch IPA with Frida Gadget**
4. Set `ipa_url` (direct download link to the IPA), plus the other options
5. Example `ipa_url` for DVIA: https://github.com/prateek147/DVIA-v2/releases/download/v2.0/DVIA-v2-swift.ipa
6. When the run finishes, it creates a **draft GitHub Release** containing the output IPA
7. You can download that IPA and install it within your jailed device
