import cairosvg, re

base = open('/tmp/icongen/icon.svg').read()
# add clipPath def once
base = base.replace('</defs>',
    '<clipPath id="circ"><circle cx="512" cy="512" r="512"/></clipPath></defs>')

def round_variant(svg):
    head, tail = svg.split('</defs>', 1)
    body = tail.rsplit('</svg>', 1)[0]
    return head + '</defs><g clip-path="url(#circ)">' + body + '</g></svg>'

def write(name, svg_text, size):
    cairosvg.svg2png(bytestring=svg_text.encode(), write_to=name,
                     output_width=size, output_height=size)

res = '/Users/steven/workspace/safeguard/linkatlas/android/app/src/main/res'
for d, px in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
    write(f'{res}/mipmap-{d}/ic_launcher.png', base, px)
    write(f'{res}/mipmap-{d}/ic_launcher_round.png', round_variant(base), px)

fg = base
fg = re.sub(r'<rect width="1024" height="1024" fill="url\(#bg\)"/>', '', fg)
fg_sizes = {'mdpi':108,'hdpi':162,'xhdpi':216,'xxhdpi':324,'xxxhdpi':432}
for d, px in fg_sizes.items():
    write(f'{res}/mipmap-{d}/ic_launcher_foreground.png', fg, px)

write('/Users/steven/workspace/safeguard/linkatlas/ios/App/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png', base, 1024)
print('done')
