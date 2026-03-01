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
