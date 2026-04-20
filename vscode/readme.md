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

### [Command Runner](https://marketplace.visualstudio.com/items?itemName=edonet.vscode-command-runner)

Create custom keyboard commands such as [`toggleLinePrefix.ts`](toggleLinePrefix.ts).

#### Settings

```json
"command-runner.commands": {
	"Toggle Line Prefix": "${homedir}/Developer/scripts/vscode/toggleLinePrefix.ts --file=${file} --line=${lineNumber} --prefix=//",
},
```

#### Keybindings

```json
{
	"key": "cmd+/",
	"command": "command-runner.run",
	"args": {
		"command": "Toggle Line Prefix"
	},
	"when": "editorLangId == 'swift' && editorTextFocus && !editorReadonly"
}
```
