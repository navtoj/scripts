## Input

[Apple Documentation](https://developer.apple.com/library/archive/documentation/Xcode/Reference/xcode_ref-Asset_Catalog_Format/AppIconType.html)

### .icns

1. Run the command below.

```shell
iconutil --convert iconset AppIcon.icns
```

2. Follow the steps for an [iconset](#iconset) source.

### .iconset

1. Within the `AppIcon.iconset` folder, find the `512x512@2x` image file.
2. Follow the steps for an [Image](#image) source.

### Image

1. Rename the image to `1024.png`.
2. Run the command below.

```shell
for size in 16 32 64 128 256 512; do sips -z $size $size "1024.png" --out "${size}.png"; done
```

## Output

1. Create a folder named `AppIcon.appiconset`.
2. Move all files named `{size}.png` into it.
3. Copy the file below into the folder.

### `Contents.json`

```json
{
	"images": [
		{
			"filename": "16.png",
			"idiom": "mac",
			"scale": "1x",
			"size": "16x16"
		},
		{
			"filename": "32.png",
			"idiom": "mac",
			"scale": "2x",
			"size": "16x16"
		},
		{
			"filename": "32.png",
			"idiom": "mac",
			"scale": "1x",
			"size": "32x32"
		},
		{
			"filename": "64.png",
			"idiom": "mac",
			"scale": "2x",
			"size": "32x32"
		},
		{
			"filename": "128.png",
			"idiom": "mac",
			"scale": "1x",
			"size": "128x128"
		},
		{
			"filename": "256.png",
			"idiom": "mac",
			"scale": "2x",
			"size": "128x128"
		},
		{
			"filename": "256.png",
			"idiom": "mac",
			"scale": "1x",
			"size": "256x256"
		},
		{
			"filename": "512.png",
			"idiom": "mac",
			"scale": "2x",
			"size": "256x256"
		},
		{
			"filename": "512.png",
			"idiom": "mac",
			"scale": "1x",
			"size": "512x512"
		},
		{
			"filename": "1024.png",
			"idiom": "mac",
			"scale": "2x",
			"size": "512x512"
		}
	],
	"info": {
		"author": "xcode",
		"version": 1
	}
}
```

## Source

[Icon Kitchen](https://icon.kitchen)

### Encode

```shell
JSON='{
  "values": {
    "fgClipart": {
      "set": "default",
      "icon": "space_bar"
    },
    "fgColor": "#ffffff",
    "bgColor": "#424242",
    "fgPadding": {
      "top": 13,
      "right": 13,
      "bottom": 13,
      "left": 13
    },
    "fgEffects": "shadow"
  },
  "modules": [
    "macos"
  ]
}'
printf '%s' "$JSON" | gzip -n | base64 | tr '+/' '-_' | tr -d '=\n' | awk '{print "https://icon.kitchen/i/"$0}'
```

### Decode

```shell
URL="https://icon.kitchen/i/H4sIAAAAAAAAA02PvQ6DMAyE5_AUlWeWqlvXqnv3qqqcP4gaMEoMDIh3bxJQy2Z_Z_vOSyVgQj-aCNfTUgkBtrl5N2DgHQiIJtegjcXRM9QFOkV9pnFAZd4SAyS81vsF8hSyKj2qT9kA-adz69jAPvtArV3f_NyYhlSfL5tNcE3Lh14SM3UH4I3d9IP93VqjOJZ4LWqaU7asQUd69OXVZ57sUFFM2qtav6PIQ3wIAQAA"
echo "${URL##*/}" | tr '_-' '/+' | awk '{p=(4-length%4)%4; while(p--)$0=$0"="; print}' | base64 -d | gunzip | jq
```
