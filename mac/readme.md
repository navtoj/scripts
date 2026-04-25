### Guides

- [How to create an app icon?](create-app-icon.md)
- [How to set up mutual TLS?](mutual-tls.md)

### Disable System Upgrade

```shell
# remove profile, if exists
profiles -C | grep -q disable.upgrade && sudo profiles -R -p disable.upgrade

# download profile
curl -fsSL https://raw.githubusercontent.com/navtoj/scripts/main/mac/disable.upgrade.mobileconfig -o /tmp/disable.upgrade.mobileconfig

# load profile
open /tmp/disable.upgrade.mobileconfig

# install profile
open "x-apple.systempreferences:com.apple.preferences.configurationprofiles"
```

### QEMU Alpine VM

<!-- curl -H "Accept: application/vnd.github.raw" -fsSL "https://api.github.com/repos/navtoj/scripts/contents/mac/qemu.alpine.ts" -->

```shell
curl -fsSL https://raw.githubusercontent.com/navtoj/scripts/main/mac/qemu.alpine.ts | bash
```

<details>
<summary>To remove, run with <code>--uninstall</code> flag.</summary>

```shell
bash <(curl -fsSL https://raw.githubusercontent.com/navtoj/scripts/main/mac/qemu.alpine.ts) --uninstall
```

</details>

### YT-DLP

```shell
curl -fsSL https://raw.githubusercontent.com/navtoj/scripts/main/mac/yt-dlp.sh | bash
```

### Dock Finder Intercept

```shell
NAME=dock-finder-intercept

# Compile Script

sudo swiftc -O "${NAME}.swift" -o "/usr/local/bin/${NAME}"

# Create Launch Agent

LAUNCH_AGENT="$HOME/Library/LaunchAgents/com.${NAME//-/.}.plist"
mkdir -p "$(dirname "$LAUNCH_AGENT")"
ln -sf "$(pwd)/${NAME}.xml" "$LAUNCH_AGENT"

# Start on Login

launchctl unload "$LAUNCH_AGENT" 2>/dev/null
launchctl load "$LAUNCH_AGENT"
```

### Remap Spotlight Key

```shell
NAME=remap-f4-to-f13

# Create Launch Agent

LAUNCH_AGENT="$HOME/Library/LaunchAgents/com.${NAME//-/.}.plist"
mkdir -p "$(dirname "$LAUNCH_AGENT")"
ln -sf "$(pwd)/${NAME}.xml" "$LAUNCH_AGENT"

# Start on Login

launchctl unload "$LAUNCH_AGENT" 2>/dev/null
launchctl load "$LAUNCH_AGENT"

# Set F13 to Screenshot

BUNDLE_ID=com.apple.screenshot.launcher
echo "f13 : pkill -f '"${BUNDLE_ID//./\\.}"' || open -b ${BUNDLE_ID}" >> .config/skhd/skhdrc
```

> [!NOTE]
> Install `skhd` with `brew install jackielii/tap/skhd-zig`.
