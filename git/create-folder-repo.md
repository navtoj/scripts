### Clone Repository

```
git clone https://github.com/user/repo.git
```

### Open Directory

```
cd repo
```

### Filter Folder

```
git filter-repo --force --subdirectory-filter path/to/folder
```

### Sign Commits

```
git rebase --root --gpg-sign --committer-date-is-author-date
```

### Set Repository

```
git remote add origin https://github.com/user/new-repo.git
```

<!-- https://github.com/new?visibility=private&name=new-repo -->

### Set Branch Name

```
git branch --move main
```

### Publish Branch

```
git push --force --set-upstream origin main
```
