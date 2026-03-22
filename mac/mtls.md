## mTLS

[smallstep/step](https://smallstep.com/docs/step-cli)

```shell
USER="user" # navtoj
DEVICE="device" # laptop, phone, etc.
SERVICE="Service" # WireGuard, OpenVPN, etc.

user=$(echo "$USER" | tr '[:upper:]' '[:lower:]')
device=$(echo "$DEVICE" | tr '[:upper:]' '[:lower:]')
service=$(echo "$SERVICE" | tr '[:upper:]' '[:lower:]')
```

### Create Root Certificate

Enter a password for the `root` certificate.

```shell
printf "Root Password: " && read -rs ROOT_PASSWORD && echo -n "$ROOT_PASSWORD" | wc -c
```

**Duration:** 10 Years

```shell
step certificate create --force --profile root-ca --not-after=87600h --password-file=<(printf '%s' "$ROOT_PASSWORD") "$SERVICE Root CA" root.crt root.key
```

Move `root` certificate to the server's `certs` folder.

> [!IMPORTANT]
> Backup `root.key` in a secure offline location.
>
> It is required to create future `leaf` certificates.

#### Verify Password

```shell
step crypto key inspect root.key --password-file=<(printf '%s' "$ROOT_PASSWORD")
```

### Create Leaf Certificate

Enter a password for the `leaf` certificate.

```shell
printf "Leaf Password: " && read -rs LEAF_PASSWORD && echo -n "$LEAF_PASSWORD" | wc -c
```

**Duration:** 1 Year

<!-- 2027-01-01T00:00:00Z -->

```shell
step certificate create --force --profile leaf --not-after=8760h --ca root.crt --ca-key root.key --ca-password-file=<(printf '%s' "$ROOT_PASSWORD") --password-file=<(printf '%s' "$LEAF_PASSWORD") --san "$user.$device" "$user.$device" "$user.$device.crt" "$user.$device.key"
```

Move `leaf` certificate to the server's `client` folder.

### Create Client Bundle

```shell
p12_bundle() {
	[[ $# -gt 1 || ( $# -eq 1 && "$1" != "legacy" ) ]] && { echo "Usage: p12_bundle [legacy]" >&2; return 1; }

	LEAF_PASSWORD="$LEAF_PASSWORD" openssl pkcs12 -export ${1:+-legacy} -certfile root.crt -in "$user.$device.crt" -inkey "$user.$device.key" -passin env:LEAF_PASSWORD -out "$user.$device.${1:+legacy.}p12" -passout env:LEAF_PASSWORD
}
```

#### Android

```shell
p12_bundle
```

`Encryption & credentials` &rsaquo; `Install a certificate` &rsaquo; `VPN & app user certificate`

#### macOS

```shell
p12_bundle legacy
```

<!--
> [!NOTE]
> Set `When using this certificate` to `Always Trust` in macOS Keychain.
-->

```shell
service_uuid() {
    python3 -c "import uuid; print(uuid.uuid5(uuid.NAMESPACE_DNS, 'com.$user.$service.$1'))"
}
```

```shell
cat > "$user.$device.mobileconfig" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadIdentifier</key>
	<string>com.$user.$service.client</string>
	<key>PayloadUUID</key>
	<string>$(service_uuid client)</string>
	<key>PayloadDisplayName</key>
	<string>$SERVICE Client</string>
	<key>PayloadDescription</key>
	<string>Enables remote access to $SERVICE.</string>
	<key>PayloadOrganization</key>
	<string>$SERVICE</string>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadIdentifier</key>
			<string>com.$user.$service.root</string>
			<key>PayloadUUID</key>
			<string>$(service_uuid root)</string>
			<key>PayloadDisplayName</key>
			<string>$SERVICE Root CA</string>
			<key>PayloadContent</key>
			<data>$(openssl x509 -in root.crt -outform DER | base64)</data>
		</dict>
		<dict>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadType</key>
			<string>com.apple.security.pkcs12</string>
			<key>PayloadIdentifier</key>
			<string>com.$user.$service.leaf</string>
			<key>PayloadUUID</key>
			<string>$(service_uuid leaf)</string>
			<key>PayloadDisplayName</key>
			<string>$SERVICE Leaf</string>
			<key>PayloadContent</key>
			<data>$(base64 < "$user.$device.legacy.p12")</data>
		</dict>
	</array>
</dict>
</plist>
EOF
```

`System Settings` &rsaquo; `General` &rsaquo; `Device Management`

```shell
open x-apple.systempreferences:com.apple.Profiles-Settings.extension
```

<!--
<key>PayloadRemovalDisallowed</key>
<true/>
<key>AllowAllAppsAccess</key>
<false/>
<key>Password</key>
<string>$LEAF_PASSWORD</string>
-->

### Cleanup Artifacts

```shell
# rm -rf root.crt
# rm -rf root.key
# rm -rf "$user.$device.crt"
rm -rf "$user.$device.key"
# rm -rf "$user.$device.p12"
rm -rf "$user.$device.legacy.p12"
# rm -rf "$user.$device.mobileconfig"
```

```shell
unset USER
unset user

unset DEVICE
unset device

unset SERVICE
unset service

unset ROOT_PASSWORD
unset LEAF_PASSWORD

unset -f p12_bundle
unset -f service_uuid
```
