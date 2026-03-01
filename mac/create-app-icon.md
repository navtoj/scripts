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
3. Create a `Contents.json` file inside with the content below.

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
