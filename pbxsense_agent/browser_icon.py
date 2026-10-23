"""Dependency-free ICO rendering of the same vector beacon used by the Agent."""
from functools import lru_cache
import math
import struct
import zlib


@lru_cache(maxsize=1)
def favicon_ico():
    size, samples = 64, 3
    rows = bytearray()
    for y in range(size):
        rows.append(0)  # PNG scanline filter.
        for x in range(size):
            alpha = 0.0
            for sy in range(samples):
                for sx in range(samples):
                    dx = (x + (sx + .5) / samples) * 32 / size - 16
                    dy = (y + (sy + .5) / samples) * 32 / size - 16
                    distance = math.hypot(dx, dy)
                    angle = math.degrees(math.atan2(dy, dx)) % 360
                    a = 1.0 if distance <= 3.7 else 0.0
                    for radius, rotation, dash, opacity in ((8.8, 17, 44.6, .68), (13.9, 123, 54.9, .45)):
                        end = dash / radius * 180 / math.pi
                        relative = (angle - rotation) % 360
                        on_stroke = abs(distance-radius) <= 1.2 and relative <= end
                        # SVG's rounded ends are circles at the dash endpoints.
                        for degrees in (rotation, rotation+end):
                            radians = math.radians(degrees)
                            on_stroke |= math.hypot(dx-radius*math.cos(radians), dy-radius*math.sin(radians)) <= 1.2
                        if on_stroke:
                            a = opacity + a * (1-opacity)
                    alpha += a
            rows.extend((0x75, 0xd4, 0x9b, round(255*alpha/(samples*samples))))

    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind+data) & 0xffffffff)
    png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!IIBBBBB', size, size, 8, 6, 0, 0, 0))
           + chunk(b'IDAT', zlib.compress(bytes(rows))) + chunk(b'IEND', b''))
    return struct.pack('<HHH', 0, 1, 1) + struct.pack('<BBBBHHII', size, size, 0, 0, 1, 32, len(png), 22) + png
