#!/usr/bin/env python3
"""Render assets/hero.png, the README banner, from real signature data.

Draws the crypto_clipper fingerprint (specimen bars plus the family reference contour) under
the headline, in the console palette, so the front page and the interactive console share one
identity. Regenerate after assets/fingerprints.json changes:

    python assets/render_hero.py
"""
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
DEJAVU = "/usr/share/fonts/truetype/dejavu/"
BG=(15,18,22); INK=(231,236,241); MUTED=(138,149,161); FAINT=(95,106,117)
ACCENT=(53,196,212); LINE=(37,43,50)
W, H, S = 1200, 470, 2   # supersample by S then downscale


def font(name, size):
    return ImageFont.truetype(DEJAVU + name, size * S)


def main():
    img = Image.new("RGB", (W*S, H*S), BG)
    d = ImageDraw.Draw(img)
    serif = font("DejaVuSerif-Bold.ttf", 44)
    wordmark = font("DejaVuSerif-Bold.ttf", 20)
    sans = font("DejaVuSans.ttf", 18)
    mono = font("DejaVuSansMono.ttf", 17)
    mono_s = font("DejaVuSansMono.ttf", 14)
    pad = 56 * S

    # wordmark
    d.text((pad, 40*S), "3", font=wordmark, fill=INK)
    wb = d.textbbox((0, 0), "3", font=wordmark)
    d.text((pad + wb[2]-wb[0], 40*S), "S", font=wordmark, fill=ACCENT)

    d.text((pad, 92*S), "Every behavior leaves a fingerprint.", font=serif, fill=INK)
    d.text((pad, 158*S), "A small model reads what code does and reduces it to a vector.",
           font=sans, fill=MUTED)
    d.text((pad, 186*S), "Same behavior, similar vector, even renamed, reformatted, or obfuscated.",
           font=sans, fill=MUTED)

    s = json.loads((HERE/"fingerprints.json").read_text())["samples"][0]  # crypto_clipper
    fp, ref = s["fp"], s["famfp"]
    n = len(fp)
    x0, x1, mid, amp = pad, W*S-pad, 320*S, 66*S
    bw = (x1-x0)/n
    scale = max(max(abs(v) for v in fp), max(abs(v) for v in ref)) or 1

    d.line([(x0, mid), (x1, mid)], fill=LINE, width=S)
    for i in range(n):
        v = fp[i]/scale*amp
        bx = x0 + i*bw + bw*0.16
        y0, y1 = min(mid, mid-v), max(mid, mid-v)
        d.rectangle([bx, y0, bx+bw*0.68, y1], fill=ACCENT)
    d.line([(x0+i*bw+bw/2, mid - ref[i]/scale*amp) for i in range(n)],
           fill=MUTED, width=2*S, joint="curve")

    d.text((pad, 400*S), "3S:microsoft/phi-1_5/", font=mono, fill=MUTED)
    ab = d.textbbox((0, 0), "3S:microsoft/phi-1_5/", font=mono)
    d.text((pad + ab[2]-ab[0], 400*S), "crypto_clipper", font=mono, fill=ACCENT)
    cap = "wallet_hook.js  signed, matched, blocked"
    cb = d.textbbox((0, 0), cap, font=mono_s)
    d.text((x1 - (cb[2]-cb[0]), 403*S), cap, font=mono_s, fill=FAINT)

    img.resize((W, H), Image.LANCZOS).save(HERE/"hero.png")
    print("wrote", HERE/"hero.png")


if __name__ == "__main__":
    main()
