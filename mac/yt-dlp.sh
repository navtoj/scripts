#!/usr/bin/env bash
mkdir -p ~/.local/bin
curl -L https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp_macos -o ~/.local/bin/yt-dlp
xattr -d com.apple.quarantine ~/.local/bin/yt-dlp
chmod a+rx ~/.local/bin/yt-dlp
yt-dlp --update
