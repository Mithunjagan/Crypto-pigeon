"""Rasterize the repo-native logo paths for desktop icons and a review preview."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parent.parent
source = root / 'apps/desktop/assets/pigeon.svg'
svg = ET.parse(source).getroot()
resolution = 1024
scale = resolution / 108
canvas = Image.new('RGBA', (resolution, resolution))
draw = ImageDraw.Draw(canvas)
draw.rounded_rectangle((0, 0, resolution - 1, resolution - 1), radius=26 * scale, fill='#101C32')
for path in svg.findall('.//{http://www.w3.org/2000/svg}path'):
    tokens = re.findall(r'[MLCZ]|-?\d+(?:\.\d+)?', path.attrib['d'])
    points = []
    cursor = 0
    position = (0., 0.)
    while cursor < len(tokens):
        command = tokens[cursor]
        cursor += 1
        if command in ('M', 'L'):
            position = (float(tokens[cursor]), float(tokens[cursor + 1]))
            cursor += 2
            points.append(position)
        elif command == 'C':
            values = list(map(float, tokens[cursor:cursor + 6]))
            cursor += 6
            start = position
            for sample in range(1, 65):
                t = sample / 64
                u = 1 - t
                points.append((u**3 * start[0] + 3*u*u*t*values[0] + 3*u*t*t*values[2] + t**3*values[4],
                               u**3 * start[1] + 3*u*u*t*values[1] + 3*u*t*t*values[3] + t**3*values[5]))
            position = tuple(values[4:6])
        elif command != 'Z':
            raise ValueError(f'Unsupported logo command: {command}')
    draw.polygon([((x * .78 + 10.14) * scale, (y * .78 + 11.7) * scale) for x, y in points], fill=path.attrib['fill'])
png = root / 'apps/desktop/assets/pigeon.png'
canvas.resize((512, 512), Image.Resampling.LANCZOS).save(png)
canvas.save(root / 'apps/desktop/assets/pigeon.ico', sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
preview = root / 'artifacts/pigeon-logo-preview.png'
canvas.resize((512, 512), Image.Resampling.LANCZOS).save(preview)
print(preview)
