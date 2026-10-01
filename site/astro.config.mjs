// @ts-check
import fs from 'node:fs';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import starlightLlmsTxt from 'starlight-llms-txt';
import starlightPageActions from 'starlight-page-actions';
import { base, repoUrl, siteUrl } from './site.config.mjs';

const description =
  'porthole is a self-hosted ngrok alternative: expose localhost to the internet through your own server, SSH into machines behind NAT, and let AI agents (Claude Code or any MCP client) manage the tunnels.';

// Pages are copied from the repository by scripts/sync-docs.mjs before the build; a page that does not exist
// (yet) is left out of the sidebar instead of failing the build.
const exists = (/** @type {string} */ slug) =>
  ['md', 'mdx'].some((ext) => fs.existsSync(new URL(`./src/content/docs/${slug}.${ext}`, import.meta.url)));
const page = (/** @type {string} */ slug, /** @type {string} */ label) =>
  exists(`docs/${slug}`) ? [{ slug: `docs/${slug}`, label }] : [];

export default defineConfig({
  site: siteUrl,
  base,
  trailingSlash: 'always',
  devToolbar: { enabled: false },
  integrations: [
    starlight({
      title: 'porthole',
      description,
      logo: { src: './src/assets/logo.svg', alt: 'porthole' },
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: repoUrl }],
      editLink: { baseUrl: `${repoUrl}/edit/main/site/` },
      lastUpdated: true,
      pagefind: true,
      customCss: [
        '@fontsource-variable/inter/index.css',
        '@fontsource/jetbrains-mono/400.css',
        '@fontsource/jetbrains-mono/500.css',
        './src/styles/custom.css',
      ],
      components: {
        Head: './src/components/Head.astro',
        PageTitle: './src/components/PageTitle.astro',
        SocialIcons: './src/components/SocialIcons.astro',
      },
      head: [
        { tag: 'meta', attrs: { property: 'og:image', content: `${siteUrl}${base}/og.png` } },
        { tag: 'meta', attrs: { property: 'og:image:width', content: '1200' } },
        { tag: 'meta', attrs: { property: 'og:image:height', content: '630' } },
        {
          tag: 'meta',
          attrs: { property: 'og:image:alt', content: 'porthole: tunnels your AI agent can run, on your own server' },
        },
        { tag: 'meta', attrs: { name: 'twitter:image', content: `${siteUrl}${base}/og.png` } },
        { tag: 'link', attrs: { rel: 'apple-touch-icon', href: `${base}/apple-touch-icon.png` } },
        { tag: 'link', attrs: { rel: 'alternate', type: 'text/plain', href: `${base}/llms.txt`, title: 'llms.txt' } },
      ],
      sidebar: [
        {
          label: 'Get started',
          items: [...page('overview', 'Overview'), ...page('agent-install', 'Install with your agent'), ...page('quickstart', 'Quick start'), ...page('install', 'Install')],
        },
        {
          label: 'Guides',
          items: [
            ...page('guides', 'Use cases'),
            ...page('server', 'Server setup'),
            ...page('client', 'Client'),
            ...page('ssh', 'SSH by name'),
            ...page('agents', 'Agents (MCP)'),
            ...page('for-ai-assistants', 'For AI assistants'),
            ...page('recipes', 'Recipes'),
            ...page('deploy', 'Deploy'),
          ],
        },
        { label: 'Reference', items: [...page('protocol', 'Wire protocol')] },
        { label: 'Concepts', items: [...page('design', 'Design'), ...page('security', 'Security')] },
        { label: 'Architecture decisions', collapsed: true, items: [{ autogenerate: { directory: 'docs/adr' } }] },
        {
          label: 'Project',
          items: [
            ...page('troubleshooting', 'Troubleshooting'),
            ...page('faq', 'FAQ'),
            ...page('contributing', 'Contributing'),
            { label: 'Releases and changelog', link: `${repoUrl}/releases` },
          ],
        },
      ],
      plugins: [
        starlightLinksValidator({ errorOnRelativeLinks: false }),
        starlightLlmsTxt({
          projectName: 'porthole',
          description:
            'porthole is a self-hosted, open-source (Apache-2.0) alternative to ngrok, written in Go. You run one server (`portholed`) on a machine with a public IP address and a domain, and a client (`porthole`) on any machine behind NAT. It exposes localhost over HTTPS, TCP services on a reserved port and SSH by name (`ssh -J`), and it has built-in MCP servers so an AI agent (Claude Code or any MCP client) can open tunnels, inspect traffic and enrol machines. Status: alpha.',
          details:
            'Use the "For AI assistants" page for step-by-step instructions to follow when a user asks to expose a service or reach a machine behind NAT. All commands are taken from the documentation; examples use the domain `tun.example.com` and the client name `home`.',
          promote: ['docs/agent-install', 'docs/for-ai-assistants', 'docs/quickstart', 'docs/agents', 'docs/faq', 'docs/install'],
          demote: ['docs/adr/**', 'docs/protocol'],
          optionalLinks: [
            { label: 'Source code and releases', url: repoUrl, description: 'GitHub repository, issues and signed releases' },
          ],
        }),
        starlightPageActions({
          actions: { markdown: true, chatgpt: true, claude: true },
          share: false,
        }),
      ],
    }),
  ],
});
