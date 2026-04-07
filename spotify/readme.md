## Spicetify

> Run [`spotx-bash`](https://github.com/SpotX-Official/SpotX-Bash) before [`spicetify`](https://github.com/spicetify/cli).

### Theme

```shell
THEME="Minimal"
ln -sf "$(pwd)" ~/.config/spicetify/Themes/"${THEME}"
spicetify config current_theme "${THEME}" --quiet
spicetify apply --quiet
```

### Extensions

- Spicy Lyrics
- Autoplay
- Shuffle+
- Queue Time
- Full Queue Clear
