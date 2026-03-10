#!/usr/bin/env bash
if ! command -v yt-dlp >/dev/null 2>&1; then
	mkdir -p ~/.local/bin
	curl -L https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp_macos -o ~/.local/bin/yt-dlp
	xattr -d com.apple.quarantine ~/.local/bin/yt-dlp
	chmod a+rx ~/.local/bin/yt-dlp
	echo "yt-dlp installed to ~/.local/bin/yt-dlp"
fi
yt-dlp --update
