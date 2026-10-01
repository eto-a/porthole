// Copies the repository documents into src/content/docs/docs/ so Starlight can build them.
// Sources stay where they are (GitHub and README link to them); this script never writes outside site/.
//   - the title comes from the first "# H1", which is removed from the body (Starlight renders the title itself);
//   - relative links are rewritten to site routes, or to GitHub for files that are not part of the site;
//   - editUrl points at the source file on GitHub; lastUpdated is the date of the last commit of the source.
// A source that does not exist (for example a page another change has not added yet) is skipped without an error.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { base, branch, repoUrl } from '../site.config.mjs';

const siteDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(siteDir, '..');
const outDir = path.join(siteDir, 'src', 'content', 'docs', 'docs');

// Repo-relative source -> route (below /docs/). Directories are listed by glob below.
const named = {
  'README.md': { slug: 'overview', title: 'Overview' },
  'DESIGN.md': { slug: 'design', title: 'Design' },
  'SECURITY.md': { slug: 'security', title: 'Security policy' },
  'CONTRIBUTING.md': { slug: 'contributing', title: 'Contributing' },
};

function listMd(dir) {
  const abs = path.join(repoRoot, dir);
  if (!fs.existsSync(abs)) return [];
  return fs
    .readdirSync(abs, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith('.md'))
    .map((e) => `${dir}/${e.name}`)
    .sort();
}

function slugFor(rel) {
  if (named[rel]) return named[rel].slug;
  if (rel.startsWith('docs/adr/')) return `adr/${path.basename(rel, '.md').toLowerCase()}`;
  if (rel.startsWith('docs/')) return path.basename(rel, '.md').toLowerCase();
  return null;
}

const sources = [...Object.keys(named), ...listMd('docs'), ...listMd('docs/adr')].filter((rel) =>
  fs.existsSync(path.join(repoRoot, rel)),
);
const synced = new Set(sources);

function routeFor(rel) {
  return `${base}/docs/${slugFor(rel)}/`;
}

function rewriteTarget(target, fromRel) {
  if (/^([a-z][a-z0-9+.-]*:|\/\/|#)/i.test(target)) return target;
  const [pathPart, ...rest] = target.split('#');
  const frag = rest.length ? `#${rest.join('#')}` : '';
  if (pathPart === '') return target;
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), pathPart));
  if (resolved.startsWith('..')) return target;
  if (synced.has(resolved)) return routeFor(resolved) + frag;
  const abs = path.join(repoRoot, resolved);
  const exists = fs.existsSync(abs);
  // A docs page that is not on disk (yet) still belongs to the site.
  if (!exists && /^docs\/[^/]+\.md$/.test(resolved)) return routeFor(resolved) + frag;
  const kind = exists && fs.statSync(abs).isDirectory() ? 'tree' : 'blob';
  return `${repoUrl}/${kind}/${branch}/${resolved.replace(/\/$/, '')}${frag}`;
}

function rewriteLinks(body, fromRel) {
  const out = [];
  let fence = null;
  for (const line of body.split('\n')) {
    const m = line.match(/^\s*(`{3,}|~{3,})/);
    if (m) {
      if (!fence) fence = m[1][0].repeat(m[1].length);
      else if (m[1][0] === fence[0] && m[1].length >= fence.length) fence = null;
      out.push(line);
      continue;
    }
    if (fence) {
      out.push(line);
      continue;
    }
    let l = line.replace(/(!?\[[^\]]*\]\()([^)\s]+)((?:\s+"[^"]*")?\))/g, (_, a, t, c) => a + rewriteTarget(t, fromRel) + c);
    l = l.replace(/^(\s{0,3}\[[^\]]+\]:\s*)(\S+)/, (_, a, t) => a + rewriteTarget(t, fromRel));
    out.push(l);
  }
  return out.join('\n');
}

function plain(md) {
  return md
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[`*_>]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function description(body) {
  for (const para of body.split(/\n\s*\n/)) {
    const t = para.trim();
    if (!t || /^(#|```|~~~|\||[-*]\s|\d+\.\s|<|!\[|\[!\[)/.test(t) || /^\[[^\]]+\]\s*\|/.test(t)) continue;
    const s = plain(t);
    if (s.length < 20) continue;
    return s.length > 180 ? `${s.slice(0, 177).replace(/\s+\S*$/, '')}...` : s;
  }
  return '';
}

function lastCommit(rel) {
  try {
    const out = execFileSync('git', ['log', '-1', '--format=%cI', '--', rel], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (out) return out;
  } catch {
    // no git or no history: fall through
  }
  return fs.statSync(path.join(repoRoot, rel)).mtime.toISOString();
}

// Structured data (schema.org) for search engines and LLM crawlers: FAQPage for the FAQ, HowTo for the quick start.
function sections(body, level) {
  const out = [];
  const head = new RegExp(`^#{${level}}\\s+(.+)$`);
  let cur = null;
  let fence = false;
  for (const line of body.split('\n')) {
    if (/^\s*(`{3,}|~{3,})/.test(line)) {
      fence = !fence;
      continue;
    }
    if (fence) continue;
    const m = line.match(head);
    if (m) {
      cur = { heading: plain(m[1]), text: [] };
      out.push(cur);
    } else if (/^#{1,6}\s/.test(line)) {
      cur = null;
    } else if (cur) {
      cur.text.push(line);
    }
  }
  return out.map((x) => ({ heading: x.heading, text: plain(x.text.join(' ')) }));
}

function headLd(obj) {
  const json = JSON.stringify(obj).replace(/</g, '\u003c');
  return `head: [{"tag":"script","attrs":{"type":"application/ld+json"},"content":${JSON.stringify(json)}}]`;
}

function jsonLd(slug, desc, body) {
  if (slug === 'faq') {
    const qs = sections(body, 2).filter((q) => q.text);
    if (!qs.length) return [];
    return [
      headLd({
        '@context': 'https://schema.org',
        '@type': 'FAQPage',
        mainEntity: qs.map((q) => ({ '@type': 'Question', name: q.heading, acceptedAnswer: { '@type': 'Answer', text: q.text } })),
      }),
    ];
  }
  if (slug === 'quickstart') {
    const steps = sections(body, 2).filter((x) => /^\d+\.\s/.test(x.heading) && x.text);
    if (!steps.length) return [];
    return [
      headLd({
        '@context': 'https://schema.org',
        '@type': 'HowTo',
        name: 'Expose a local service to the internet with porthole',
        description: desc,
        step: steps.map((x, i) => ({
          '@type': 'HowToStep',
          position: i + 1,
          name: x.heading.replace(/^\d+\.\s*/, ''),
          text: x.text.length > 500 ? `${x.text.slice(0, 497)}...` : x.text,
        })),
      }),
    ];
  }
  return [];
}

function prepareReadme(text) {
  // The README starts with badges and a row of links meant for GitHub; the site has its own navigation.
  const link = '\\[[^\\]]+\\]\\([^)]+\\)';
  const navRow = new RegExp(`^${link}( \\| ${link})*( \\|)?$`);
  return text
    .split(/\n\s*\n/)
    .filter((para) => {
      const lines = para.trim().split('\n');
      const badges = lines.every((l) => l.startsWith('[!['));
      const nav = para.includes(' | ') && lines.every((l) => navRow.test(l));
      return !badges && !nav;
    })
    .join('\n\n');
}

// Remove what the previous run generated (hand-written pages live in the same directory and stay).
const manifestPath = path.join(outDir, '.sync-manifest.json');
if (fs.existsSync(manifestPath)) {
  for (const f of JSON.parse(fs.readFileSync(manifestPath, 'utf8'))) fs.rmSync(path.join(outDir, f), { force: true });
}
const written = [];
let count = 0;
for (const rel of sources) {
  let text = fs.readFileSync(path.join(repoRoot, rel), 'utf8').replace(/\r\n/g, '\n');
  if (rel === 'README.md') text = prepareReadme(text);
  const lines = text.split('\n');
  const h1 = lines.findIndex((l) => /^#\s+\S/.test(l));
  let title = named[rel]?.title;
  if (h1 >= 0) {
    title ??= lines[h1].replace(/^#\s+/, '').trim();
    lines.splice(h1, 1);
  }
  title ??= path.basename(rel, '.md');
  let body = rewriteLinks(lines.join('\n'), rel).replace(/^\n+/, '');
  const desc = description(body);
  const fm = [
    '---',
    `title: ${JSON.stringify(title.replace(/`/g, ''))}`,
    ...(desc ? [`description: ${JSON.stringify(desc)}`] : []),
    `editUrl: ${repoUrl}/edit/${branch}/${rel}`,
    `lastUpdated: ${lastCommit(rel)}`,
    ...jsonLd(slugFor(rel), desc, body),
    '---',
    '',
  ].join('\n');
  const dest = path.join(outDir, `${slugFor(rel)}.md`);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, fm + body.replace(/\n*$/, '\n'), { encoding: 'utf8' });
  written.push(path.relative(outDir, dest).split(path.sep).join('/'));
  count++;
}
fs.writeFileSync(manifestPath, `${JSON.stringify(written, null, 1)}\n`);
console.log(`sync-docs: ${count} files -> ${path.relative(siteDir, outDir)}`);
