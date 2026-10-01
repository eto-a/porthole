// Checks the internal links of the built site (dist/): every href/src below the base path must point at an
// existing file, and a #fragment must match an id in the target page. External links are not fetched.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { base } from '../site.config.mjs';

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const pages = [];
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.endsWith('.html')) pages.push(p);
  }
})(dist);

const ids = new Map();
const idsOf = (file) => {
  if (!ids.has(file)) {
    const html = fs.readFileSync(file, 'utf8');
    ids.set(file, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
  }
  return ids.get(file);
};

let checked = 0;
const bad = [];
for (const page of pages) {
  const html = fs.readFileSync(page, 'utf8');
  const from = `/${path.relative(dist, page).split(path.sep).join('/')}`;
  for (const m of html.matchAll(/\s(?:href|src)="([^"]+)"/g)) {
    const url = m[1].replace(/&amp;/g, '&');
    if (!url.startsWith(`${base}/`) && !url.startsWith('#')) continue;
    const [target, frag] = url.split('#');
    let file = target ? path.join(dist, target.slice(base.length).split('?')[0]) : page;
    if (target && fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
    checked++;
    if (!fs.existsSync(file)) {
      bad.push(`${from}: ${url} (no such file)`);
    } else if (frag && file.endsWith('.html') && !idsOf(file).has(decodeURIComponent(frag))) {
      bad.push(`${from}: ${url} (no such anchor)`);
    }
  }
}
console.log(`check-links: ${pages.length} pages, ${checked} internal links, ${bad.length} broken`);
if (bad.length) {
  console.log([...new Set(bad)].join('\n'));
  process.exit(1);
}
