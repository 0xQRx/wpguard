# PoC Video Recording Specification

## Overview

Automated generation of video proof-of-concept recordings for WordPress vulnerability demonstrations. Produces both terminal-based (Python PoC execution) and browser-based (Playwright UI walkthrough) recordings for Wordfence Bug Bounty submissions.

## System Requirements

### Core Dependencies

| Tool | Version | Purpose | Install |
|------|---------|---------|---------|
| **Python 3.10+** | 3.13 tested | PoC script execution | System package |
| **Playwright** | 1.58+ (Python) | Browser automation + video recording | `pipx install playwright` |
| **Chromium** | Bundled with Playwright | Headless browser for video capture | `playwright install chromium` |
| **asciinema** | 2.4+ | Terminal session recording to `.cast` | `pipx install asciinema` |
| **ffmpeg** | 6.0+ | Video format conversion (webm/cast → gif) | `apt install ffmpeg` |
| **svg-term-cli** | 2.1+ | Convert `.cast` → animated SVG | `npx svg-term-cli` (Node.js) |
| **Node.js** | 18+ | Required for svg-term-cli | System package |

### Optional Dependencies

| Tool | Purpose | Install |
|------|---------|---------|
| **agg** | Direct cast → GIF (higher quality than SVG route) | `cargo install agg` (requires Rust) |
| **Docker** | Sandbox container access for WP-CLI setup steps | System package |

### Python Packages

```
playwright>=1.58.0
asciinema>=2.4.0
requests>=2.28.0
```

### Verification Commands

```bash
# Check all dependencies
python3 --version            # 3.10+
playwright --version          # 1.58+
asciinema --version           # 2.4+
ffmpeg -version | head -1     # 6.0+
npx svg-term-cli --version    # 2.1+
docker --version              # For sandbox WP-CLI
```

## Output Formats

| Format | Extension | Use Case | Quality | Size |
|--------|-----------|----------|---------|------|
| **Browser GIF** | `.gif` | Wordfence submission, GitHub issues | Good | 2-8MB |
| **Browser WebM** | `.webm` | Full quality playback | Best | 2-5MB |
| **Terminal GIF** | `.gif` | Inline in markdown reports | Good | 100-500KB |
| **Terminal SVG** | `.svg` | Embedding in HTML reports (sharpest) | Best | 200-600KB |
| **Terminal WebM** | `.webm` | Video player playback | Good | 50-200KB |
| **asciinema Cast** | `.cast` | Interactive replay (`asciinema play`) | Lossless | 10-50KB |

## Architecture

### Recording Pipeline

```
                    PoC Script (poc.py)
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
     Terminal Recording          Browser Recording
     (asciinema rec)             (Playwright + recordVideo)
              │                         │
              ▼                         ▼
         .cast file                 .webm file
              │                         │
     ┌────────┴────────┐               ▼
     ▼                 ▼          ffmpeg palettegen
  svg-term         Playwright          │
     │             render SVG          ▼
     ▼                │            .gif file
  .svg file           ▼
     │            .webm file
     ▼                │
  Playwright          ▼
  render SVG     ffmpeg palettegen
     │                │
     ▼                ▼
  .webm file      .gif file
     │
     ▼
  ffmpeg palettegen
     │
     ▼
  .gif file
```

### Terminal Recording Flow

1. **Record**: `asciinema rec` wraps a demo shell script that executes the PoC
2. **Demo script**: Adds visual formatting (colored banners, simulated typing, step labels)
3. **Convert**: `.cast` → `.svg` via `svg-term-cli` → `.webm` via Playwright SVG render → `.gif` via ffmpeg

### Browser Recording Flow

1. **Setup**: Fresh sandbox with plugin installed, attacker user created
2. **Record**: Playwright `context.record_video_dir` captures all browser activity
3. **Script**: Navigates through exploit steps with overlay banners explaining each phase
4. **Convert**: `.webm` → `.gif` via ffmpeg with palette optimization

## Component Specifications

### Demo Shell Script (Terminal Recording)

The demo script wraps the PoC execution with visual formatting:

```bash
# Required functions:
type_slow()     # Simulates typing for readability
run_cmd()       # Echoes command with prompt, then executes
add_banner()    # Displays colored section headers

# Required sections:
# 1. Title card (vuln name, CVSS, plugin version)
# 2. Environment verification (curl target, plugin list)
# 3. Attacker role verification (user get)
# 4. PoC execution (python3 poc.py ...)
# 5. Result card (success/failure)
```

### Browser Video Script (Playwright)

```python
# Required components:
def add_overlay(page, text, color, duration)  # Full-screen explanation card
def add_banner(page, text, bg)                # Persistent top banner
def setup_contact_via_cli()                   # WP-CLI preconditions
def run_exploit_api(session, contact_id)      # Actual exploit execution

# Required scenes:
# 1. Title card overlay (5s) — vuln details, CVSS, root cause
# 2. Attacker login — fill form, submit, show dashboard
# 3. Pre-exploit state — show relevant admin page/data
# 4. Exploit execution overlay — explain the HTTP request
# 5. Exploit result overlay — show response data (password, token, etc.)
# 6. Post-exploit proof — login as admin, show Settings page
# 7. End card overlay (6s) — summary with file/function/line
```

### ffmpeg GIF Conversion

```bash
# Optimized settings for quality + reasonable file size:
ffmpeg -y -i input.webm \
  -vf "fps=10,scale=960:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse=dither=bayer" \
  output.gif

# Parameters:
#   fps=10        — 10 frames/sec (balances smoothness vs size)
#   scale=960:-1  — 960px wide, proportional height
#   lanczos       — high-quality scaling algorithm
#   max_colors=128 — palette size (128 = good quality, small file)
#   dither=bayer  — ordered dithering (clean for terminal/UI content)
```

### Playwright Video Settings

```python
context = browser.new_context(
    viewport={"width": 1280, "height": 720},
    record_video_dir=VIDEO_DIR,
    record_video_size={"width": 1280, "height": 720},
)
# Notes:
#   - headless=True required for CI/server environments
#   - --no-sandbox flag needed when running as root
#   - Video saved on context.close() (not page.close())
#   - File is named with random hash — copy to known path after
```

## Sandbox Requirements

Each recording requires a **clean sandbox** to demonstrate fresh exploitation:

1. `wpguard_sandbox_destroy()` — remove all data
2. `wpguard_sandbox_start()` — fresh containers
3. Install target plugin via WP-CLI
4. Create attacker user with appropriate role
5. Any additional setup (test data, linked accounts, etc.)
6. **Both recordings use the same sandbox** if run sequentially with sandbox rebuild between them

## File Organization

```
reports/{plugin_slug}/{finding_id}/
├── poc.py                  # PoC script
├── writeup.md              # Vulnerability writeup
├── submission.md           # Wordfence submission report
├── demo_script.sh          # Terminal demo wrapper
├── record_poc.sh           # Terminal recording launcher
├── browser_poc.py          # Playwright browser recording script
├── poc_demo.cast           # Raw asciinema recording
├── poc_terminal.svg        # Animated SVG (terminal)
├── poc_terminal.webm       # Terminal video
├── poc_terminal.gif        # Terminal GIF
├── poc_browser.webm        # Browser video (full quality)
├── poc_browser.gif         # Browser GIF
└── videos/                 # Playwright raw video output
    └── *.webm
```

## Vulnerability Type Templates

### Privilege Escalation / Auth Bypass

**Terminal**: Run PoC showing attacker login → exploit request → admin credentials returned
**Browser**: Login as low-priv user → trigger exploit → login as admin → show Settings page

### SQL Injection

**Terminal**: Run PoC showing injection payload → extracted data (hashes, emails)
**Browser**: Show form/endpoint → inject payload → display extracted data overlay

### Stored XSS / CSS Injection

**Terminal**: Run PoC showing payload upload → page fetch with payload in source
**Browser**: Upload payload as Author → visit page as victim → show injected content rendering

### Missing Authorization

**Terminal**: Run PoC showing low-priv API call → unauthorized data/action returned
**Browser**: Login as subscriber → call restricted endpoint → show admin-only data accessible

### File Upload / RCE

**Terminal**: Run PoC showing file upload → file accessible on server → code execution proof
**Browser**: Upload malicious file → navigate to uploaded file → show execution result

## Limitations

- **Playwright headless video**: No hardware acceleration — recording speed is ~1x real time
- **GIF file size**: Complex browser UIs produce large GIFs (4-8MB). Terminal GIFs are much smaller (100-500KB)
- **asciinema SVG**: Animation timing from `.cast` is preserved, but SVG playback depends on browser CSS animation support
- **Docker dependency**: WP-CLI setup steps require Docker access to the sandbox container
- **No audio**: All recordings are silent (terminal and browser)

---

## QA Agent Integration

See the agent instruction addendum below for integrating video recording into the QA/submission pipeline.
