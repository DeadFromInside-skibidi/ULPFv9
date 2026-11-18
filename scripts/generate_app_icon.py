"""
Generate ULPF Desktop Application Icons
=========================================
Generates multi-resolution .ico and .png icon assets for the native desktop app.
The generated files are committed under ulpf/gui/resources/, so this only needs
re-running after a design change (requires Pillow: pip install pillow).
"""
import os
from PIL import Image, ImageDraw, ImageFont

def generate_icons(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    
    # Base size 512x512
    size = (512, 512)
    img = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Dark navy rounded background
    navy_900 = (10, 15, 30, 255)
    blue_600 = (37, 99, 235, 255)
    blue_400 = (96, 165, 250, 255)
    border_color = (30, 58, 138, 255)

    # Rounded rectangle background
    draw.rounded_rectangle([16, 16, 496, 496], radius=96, fill=navy_900, outline=border_color, width=8)

    # Inner grid / security shield graphic
    # 4 tech square blocks
    block_size = 90
    gap = 24
    cx, cy = 256, 220
    
    # 2x2 grid representing Universal Log Parsing Framework
    coords = [
        (cx - block_size - gap // 2, cy - block_size - gap // 2),
        (cx + gap // 2, cy - block_size - gap // 2),
        (cx - block_size - gap // 2, cy + gap // 2),
        (cx + gap // 2, cy + gap // 2),
    ]

    colors = [blue_600, blue_400, blue_400, (14, 165, 233, 255)]
    for (x, y), c in zip(coords, colors):
        draw.rounded_rectangle([x, y, x + block_size, y + block_size], radius=20, fill=c)

    # Connecting horizontal & vertical data pipeline lines
    draw.line([cx - block_size - gap // 2 + 45, cy, cx + gap // 2 + 45, cy], fill=(255, 255, 255, 200), width=6)
    draw.line([cx, cy - block_size - gap // 2 + 45, cx, cy + gap // 2 + 45], fill=(255, 255, 255, 200), width=6)

    # Node points
    draw.ellipse([cx - 12, cy - 12, cx + 12, cy + 12], fill=(255, 255, 255, 255))

    # Bottom badge text: "ULPF"
    # Draw simple clean polygonal lettering for ULPF
    # U
    ux = 120
    draw.line([(ux, 380), (ux, 420), (ux + 40, 420), (ux + 40, 380)], fill=(255, 255, 255, 240), width=10)
    # L
    lx = 195
    draw.line([(lx, 380), (lx, 420), (lx + 35, 420)], fill=(255, 255, 255, 240), width=10)
    # P
    px = 265
    draw.line([(px, 380), (px, 420)], fill=(255, 255, 255, 240), width=10)
    draw.line([(px, 380), (px + 35, 380), (px + 35, 402), (px, 402)], fill=(255, 255, 255, 240), width=10)
    # F
    fx = 335
    draw.line([(fx, 380), (fx, 420)], fill=(255, 255, 255, 240), width=10)
    draw.line([(fx, 380), (fx + 35, 380)], fill=(255, 255, 255, 240), width=10)
    draw.line([(fx, 400), (fx + 25, 400)], fill=(255, 255, 255, 240), width=10)

    # Save PNG
    png_path = os.path.join(output_dir, "ulpf_icon.png")
    img.save(png_path, "PNG")
    print(f"Generated {png_path}")

    # Save ICO with multiple standard resolutions
    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    ico_path = os.path.join(output_dir, "ulpf_icon.ico")
    img.save(ico_path, format="ICO", sizes=ico_sizes)
    print(f"Generated {ico_path}")

if __name__ == "__main__":
    # Written next to the GUI package so pip installs and PyInstaller builds ship them
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ulpf", "gui", "resources")
    generate_icons(out)
