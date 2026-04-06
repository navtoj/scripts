## Extensions

### [Monokai Pro](https://open-vsx.org/extension/monokai/theme-monokai-pro-vscode)

```shell
EMAIL="email@example.com"

SALT="fd330f6f-3f41-421d-9fe5-de742d0c54c0"
INPUT="${SALT}${EMAIL}"

HASH=$(printf "%s" "${INPUT}" | openssl dgst -md5 | awk '{print $NF}')
KEY=$(printf "%s" "${HASH}" | cut -c1-25 | sed 's/.\{5\}/&-/g; s/-$//')
echo "${KEY}"
```
