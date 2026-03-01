### Guides

- [How to create an app icon?](create-app-icon.md)

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
