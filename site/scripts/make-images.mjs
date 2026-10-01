// Renders public/og.png (Open Graph / Twitter card) and public/apple-touch-icon.png from scripts/og.html.
// Not part of the build: run it by hand after changing og.html. Needs Playwright (and its browsers), for example:
//   docker run --rm -v "$PWD:/work" mcr.microsoft.com/playwright:v1.49.0-noble bash -c "mkdir /pw && cd /pw && \
//     npm init -y && npm i playwright@1.49.0 && cp /work/scripts/make-images.mjs . && SITE_ROOT=/work node make-images.mjs"
import { chromium } from 'playwright';
import { fileURLToPath } from 'node:url';

// SITE_ROOT lets the script run from a directory that has Playwright installed.
const root = process.env.SITE_ROOT ? new URL(`file://${process.env.SITE_ROOT}/`) : new URL('..', import.meta.url);
const html = new URL('scripts/og.html', root);
const out = (name) => fileURLToPath(new URL(`public/${name}`, root));

const browser = await chromium.launch();
const og = await browser.newPage({ viewport: { width: 1200, height: 630 } });
await og.goto(html.href);
await og.evaluate(() => document.fonts.ready);
await og.screenshot({ path: out('og.png') });

const touch = await browser.newPage({ viewport: { width: 180, height: 180 } });
await touch.goto(`${html.href}#touch`);
await touch.evaluate(() => document.fonts.ready);
await touch.screenshot({ path: out('apple-touch-icon.png') });
await browser.close();
