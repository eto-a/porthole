# porthole website

The landing page and the documentation, built with [Astro](https://astro.build) and
[Starlight](https://starlight.astro.build). Published to GitHub Pages by `.github/workflows/pages.yml`.

The documents themselves stay where they are (`../README.md`, `../docs/`, `../DESIGN.md`, `../SECURITY.md`,
`../CONTRIBUTING.md`). `scripts/sync-docs.mjs` copies them into `src/content/docs/docs/` before every dev or build run
(title from the first `# H1`, links rewritten to site routes, `editUrl` pointing at the source on GitHub). The copies are
git-ignored; do not edit them. Pages written for the site only (`for-ai-assistants.md`) live in the same directory and
are tracked.

```console
$ npm ci
$ npm run dev          # http://localhost:4321/porthole/
$ npm run check        # astro check (types, content)
$ npm run build        # static site in dist/
$ npm run check:links  # internal links and anchors of dist/
```

Node 22 or newer. Where things are:

| Path | What |
|---|---|
| `src/pages/index.astro`, `src/components/Landing.astro` | landing page (all blocks, styles and the small tab/copy script) |
| `src/components/` | Starlight overrides: header links, page title (page actions), head |
| `src/styles/custom.css` | colours (one teal accent), fonts (self-hosted via `@fontsource`), landing layout hooks |
| `astro.config.mjs` | Starlight config, sidebar, plugins (llms.txt, page actions, link validator) |
| `site.config.mjs` | site URL, base path, repository, current release shown on the landing page |
| `public/` | favicon, `robots.txt`, `og.png`, `apple-touch-icon.png` (rendered from `scripts/og.html` by `scripts/make-images.mjs`) |

When a new release is cut, update `version` in `site.config.mjs`.
