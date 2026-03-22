## mTLS

```shell
USER="Admin"
DEVICE="Laptop"
SERVICE="Home Lab"

user=$(echo "$USER" | tr '[:upper:]' '[:lower:]')
device=$(echo "$DEVICE" | tr '[:upper:]' '[:lower:]')
service=$(echo "$SERVICE" | tr '[:upper:]' '[:lower:]')
```

### Create Certificate Authority

> Duration: 10 Years

```shell
if [ -f root.key ] || [ -f root.crt ]; then return 1; fi

openssl genrsa -out root.key 4096
openssl req -x509 -days 3650 -subj "/CN=$SERVICE CA/O=$SERVICE" -key root.key -out root.crt
```

### Create Leaf Certificate

> Duration: 1 Year

#### Server

```shell
DOMAIN="example.local"

domain=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]')
```

```shell
if [ -f server.key ] || [ -f server.csr ] || [ -f server.crt ]; then return 1; fi

openssl genrsa -out server.key 2048
openssl req -new -subj "/CN=$domain/O=$SERVICE Server" -key server.key -out server.csr
openssl x509 -req -days 825 -extfile <(printf "subjectAltName=DNS:$domain\nextendedKeyUsage=serverAuth") -CAcreateserial -CA root.crt -CAkey root.key -in server.csr -out server.crt
```

#### Client

```shell
if [ -f "$user.$device.key" ] || [ -f "$user.$device.csr" ] || [ -f "$user.$device.crt" ]; then return 1; fi

openssl genrsa -out "$user.$device.key" 2048
openssl req -new -subj "/CN=$user.$device/O=$SERVICE Client" -key "$user.$device.key" -out "$user.$device.csr"
openssl x509 -req -days 825 -extfile <(printf "extendedKeyUsage=clientAuth") -CAcreateserial -CA root.crt -CAkey root.key -in "$user.$device.csr" -out "$user.$device.crt"
```

### Install Leaf Certificate

```shell
p12_bundle() {
	[[ $# -gt 1 || ( $# -eq 1 && "$1" != "legacy" ) ]] && { echo "Usage: p12_bundle [legacy]" >&2; return 1; }

	openssl pkcs12 -export -passout pass:password -in "$user.$device.crt" -inkey "$user.$device.key" ${1:+-legacy}
}
```

#### Android

```shell
if [ -f "$user.$device.p12" ]; then return 1; fi

p12_bundle > "$user.$device.p12"
```

`Encryption & credentials`
<br>&ensp;&nbsp;&rsaquo; `Install a certificate`
<br>&emsp;&ensp;&rsaquo; `CA certificate` $${\color{lightgray}root.crt}$$
<br>&emsp;&ensp;&rsaquo; `VPN & app user certificate` $${\color{lightgray}user.device.p12}$$

> [!NOTE]
> When prompted, enter `password` to continue.

#### macOS

```shell
if [ -f "$user.$device.legacy.p12" ]; then return 1; fi

p12_bundle legacy > "$user.$device.legacy.p12"
```

```shell
security delete-certificate -t -c "$SERVICE CA" ~/Library/Keychains/login.keychain-db
security delete-identity -t -c "$user.$device" ~/Library/Keychains/login.keychain-db
```

```shell
security add-trusted-cert -k ~/Library/Keychains/login.keychain-db root.crt
security import "$user.$device.legacy.p12" -P "password" -x -k ~/Library/Keychains/login.keychain-db
```

`Keychain Access` &rsaquo; `Default Keychains` &rsaquo; `login` &rsaquo; `Certificates`

### Cleanup Artifacts

> [!CAUTION]
> Backup `root.key` & `root.srl` in a secure location.
>
> They are required to sign future `leaf` certificates.

```shell
find -E . -maxdepth 1 -type f -regex ".*.(key|csr|crt|p12|srl)" -delete

unset USER
unset user

unset DEVICE
unset device

unset SERVICE
unset service

unset DOMAIN
unset domain

unset -f p12_bundle
```
