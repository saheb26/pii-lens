"""Build docs/demo.gif from a real scan of examples/sample.txt."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from pii_lens.detector import detect, summarize
from pii_lens.render import CTA

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample.txt"
OUTPUT = ROOT / "docs" / "demo.gif"

BG = (18, 20, 24)
FG = (230, 232, 235)
RED = (220, 38, 38)
WHITE = (255, 255, 255)
GREEN = (74, 222, 128)
DOTS = ((255, 95, 87), (254, 188, 46), (40, 200, 64))

FONT = ImageFont.truetype(r"C:\Windows\Fonts\consola.ttf", 18)
BOLD = ImageFont.truetype(r"C:\Windows\Fonts\consolab.ttf", 18)

CHAR_W = FONT.getlength("M")
LINE_H = 26
PAD_X = 28
TEXT_X = 22
TITLE_H = 42
WIDTH = 1040
PANEL_W = 78


def _char_font(bold: bool) -> ImageFont.FreeTypeFont:
    return BOLD if bold else FONT


def _text_width(value: str, bold: bool = False) -> float:
    return _char_font(bold).getlength(value)


def _line_segments(line: str, line_start: int, findings: list) -> list[tuple[str, bool]]:
    segments: list[tuple[str, bool]] = []
    cursor = 0
    for finding in findings:
        local_start = finding.start - line_start
        local_end = finding.end - line_start
        if local_end <= 0 or local_start >= len(line):
            continue
        local_start = max(0, local_start)
        local_end = min(len(line), local_end)
        if local_start > cursor:
            segments.append((line[cursor:local_start], False))
        segments.append((line[local_start:local_end], True))
        cursor = local_end
    if cursor < len(line):
        segments.append((line[cursor:], False))
    return segments


def _draw_runs(
    draw: ImageDraw.ImageDraw,
    x: float,
    y: int,
    segments: list[tuple[str, bool]],
) -> None:
    for value, marked in segments:
        font = _char_font(marked)
        width = font.getlength(value)
        if marked:
            draw.rectangle((x, y + 2, x + width, y + LINE_H - 2), fill=RED)
            draw.text((x, y), value, font=font, fill=WHITE)
        else:
            draw.text((x, y), value, font=font, fill=FG)
        x += width


def _panel_lines() -> list[str]:
    body = CTA.removeprefix("🛡️ ").strip()
    words = body.split()
    lines: list[str] = []
    current = ""
    limit = (PANEL_W - 6) * CHAR_W
    for word in words:
        trial = word if not current else f"{current} {word}"
        if _text_width(trial) <= limit:
            current = trial
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def _content_lines(text: str) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    offset = 0
    for raw in text.splitlines(keepends=True):
        rows.append((raw.rstrip("\r\n"), offset))
        offset += len(raw)
    return rows


def render_frame(
    command: str,
    rows: list[tuple[str, int]],
    findings: list,
    *,
    log_lines: int,
    highlight_count: int,
    show_summary: bool,
    show_panel: bool,
    height: int,
) -> Image.Image:
    ordered = sorted(findings, key=lambda finding: finding.start)
    active = ordered[:highlight_count]
    counts = summarize(findings)
    total = len(findings)
    headline = f"[{total}] High-Risk Secrets Detected in Payload"
    breakdown = "  ".join(
        f"{entity}: {counts[entity]}" for entity in counts if counts[entity]
    )
    panel = _panel_lines()

    image = Image.new("RGB", (WIDTH, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (8, 8, WIDTH - 9, height - 9),
        radius=10,
        outline=(70, 74, 82),
        width=2,
    )
    for index, color in enumerate(DOTS):
        cx = 28 + index * 22
        draw.ellipse((cx, 22, cx + 14, 36), fill=color)
    title = "pii-lens"
    draw.text(((WIDTH - FONT.getlength(title)) / 2, 16), title, font=FONT, fill=FG)

    y = TITLE_H + 8
    prompt = "$ "
    draw.text((TEXT_X, y), prompt, font=BOLD, fill=GREEN)
    draw.text((TEXT_X + _text_width(prompt, bold=True), y), command, font=FONT, fill=FG)
    y += LINE_H * 2

    for line, start in rows[:log_lines]:
        _draw_runs(draw, TEXT_X, y, _line_segments(line, start, active))
        y += LINE_H

    if show_summary:
        y += LINE_H
        draw.text((TEXT_X, y), headline, font=BOLD, fill=RED)
        y += LINE_H
        draw.text((TEXT_X, y), breakdown, font=FONT, fill=FG)
        y += LINE_H

    if show_panel:
        y += LINE_H // 2
        inner_w = int(CHAR_W * PANEL_W)
        block_h = LINE_H * (len(panel) + 2)
        box = (TEXT_X, y, TEXT_X + inner_w, y + block_h)
        draw.rounded_rectangle(box, radius=6, outline=RED, width=2)
        text_y = y + LINE_H // 2
        first, *rest = panel
        draw.text((TEXT_X + 16, text_y), first, font=FONT, fill=FG)
        text_y += LINE_H
        for line in rest:
            draw.text((TEXT_X + 16, text_y), line, font=FONT, fill=FG)
            text_y += LINE_H

    return image


def main() -> None:
    text = SAMPLE.read_text(encoding="utf-8")
    findings = detect(text, engine="regex")
    rows = _content_lines(text)
    command = "pii-lens --file examples/sample.txt"
    stages = [
        dict(log_lines=0, highlight_count=0, show_summary=False, show_panel=False),
        dict(log_lines=4, highlight_count=0, show_summary=False, show_panel=False),
        dict(log_lines=4, highlight_count=2, show_summary=False, show_panel=False),
        dict(log_lines=4, highlight_count=4, show_summary=False, show_panel=False),
        dict(log_lines=4, highlight_count=6, show_summary=False, show_panel=False),
        dict(log_lines=4, highlight_count=6, show_summary=True, show_panel=False),
        dict(log_lines=4, highlight_count=6, show_summary=True, show_panel=True),
    ]
    probe = render_frame(
        command,
        rows,
        findings,
        log_lines=4,
        highlight_count=6,
        show_summary=True,
        show_panel=True,
        height=900,
    )
    # Measure the painted content by scanning up from the bottom for non-background pixels.
    pixels = probe.load()
    content_bottom = 0
    for scan_y in range(probe.height - 20, 0, -1):
        if any(pixels[x, scan_y] != BG for x in range(40, WIDTH - 40, 2)):
            content_bottom = scan_y
            break
    height = content_bottom + 24
    frames = [
        render_frame(command, rows, findings, height=height, **stage)
        for stage in stages
    ]
    size = (WIDTH, height)
    durations = [600, 700, 450, 450, 550, 550, 2600]
    OUTPUT.parent.mkdir(exist_ok=True)
    frames[0].save(
        OUTPUT,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes) size={size}")


if __name__ == "__main__":
    main()
