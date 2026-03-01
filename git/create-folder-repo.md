### Clone Repository

```shell
git clone https://github.com/user/repo.git
```

### Open Directory

```shell
cd repo
```

### Filter Folder

```shell
git filter-repo --force --subdirectory-filter path/to/folder
```

### Sign Commits

```shell
git rebase --root --gpg-sign --committer-date-is-author-date
```

### Set Repository

```shell
git remote add origin https://github.com/user/new-repo.git
```

<!-- https://github.com/new?visibility=private&name=new-repo -->

### Set Branch Name

```shell
git branch --move main
```

### Publish Branch

```shell
git push --force --set-upstream origin main
```
