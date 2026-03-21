### Latest Remote

```shell
git fetch origin
```

### Local Commits

```shell
local_commits=($(git rev-list --reverse HEAD))
```

### Remote Commits

```shell
remote_commits=($(git rev-list --reverse origin/main))
```

### Compare Commits

```shell
for i in "${!local_commits[@]}"; do git diff "${remote_commits[$i]}" "${local_commits[$i]}"; done
```
