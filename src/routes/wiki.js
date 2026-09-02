'use strict';

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const MarkdownIt = require('markdown-it');

const router = express.Router();

const REPO_ROOT = path.join(__dirname, '..', '..');
const DOCS_ROOT = path.join(REPO_ROOT, 'docs');

const md = new MarkdownIt({
  html: false,
  linkify: false,
  typographer: false,
});

// GitHub-style heading slugs so anchor links in the wiki resolve.
function slugify(text) {
  return text
    .toLowerCase()
    .replace(/<[^>]+>/g, '')
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .trim()
    .replace(/\s+/g, '-');
}

const defaultHeadingOpen = md.renderer.rules.heading_open || ((tokens, idx, options, env, self) => self.renderToken(tokens, idx, options));
md.renderer.rules.heading_open = (tokens, idx, options, env, self) => {
  const token = tokens[idx];
  const inline = tokens[idx + 1];
  if (inline && inline.children) {
    const text = inline.children.filter(c => c.type === 'text' || c.type === 'code_inline').map(c => c.content).join('');
    token.attrSet('id', slugify(text));
  }
  return defaultHeadingOpen(tokens, idx, options, env, self);
};

const defaultLinkOpen = md.renderer.rules.link_open || ((tokens, idx, options, env, self) => self.renderToken(tokens, idx, options));
md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
  const token = tokens[idx];
  const href = token.attrGet('href') || '';
  const rewritten = rewriteHref(href, env && env.relDir ? env.relDir : '');
  if (rewritten !== null) token.attrSet('href', rewritten);
  return defaultLinkOpen(tokens, idx, options, env, self);
};

// Rewrite relative *.md links to served /docs URLs (keeping #anchors).
// Links resolve against the page's docs-relative directory; escapes to the
// repo root (e.g. ../SECURITY.md) and README's repo-root-style docs/… links
// are mapped onto the served tree.
function rewriteHref(href, relDir) {
  if (/^(https?:|mailto:|tel:|javascript:|#|\/)/.test(href)) return null;
  const hashIndex = href.indexOf('#');
  const pathPart = hashIndex === -1 ? href : href.slice(0, hashIndex);
  const fragment = hashIndex === -1 ? '' : href.slice(hashIndex);
  const resolved = path.posix.normalize(path.posix.join(relDir, pathPart));

  let target = null;
  if (resolved.startsWith('../')) {
    const repoRel = resolved.replace(/^(\.\.\/)+/, '');
    if (repoRel && fs.existsSync(path.join(REPO_ROOT, repoRel))) target = repoRel;
  } else if (!resolved.startsWith('..')) {
    if (fs.existsSync(path.join(DOCS_ROOT, resolved))) {
      target = resolved;
    } else if (resolved.startsWith('docs/') && fs.existsSync(path.join(DOCS_ROOT, resolved.slice(5)))) {
      target = resolved.slice(5);
    } else if (fs.existsSync(path.join(REPO_ROOT, resolved))) {
      target = resolved;
    }
  }
  if (!target) return null;

  const withoutExt = target.toLowerCase().endsWith('.md') ? target.slice(0, -3) : target;
  return '/docs/' + (withoutExt === 'README' ? '' : withoutExt) + fragment;
}

function titleFromSource(source, fallback) {
  const first = source.match(/^#\s+(.+)$/m);
  return first ? first[1].trim() : fallback;
}

// ---- Page index (computed once at startup) ----

const GROUPS = [
  { dir: '', title: 'Basics' },
  { dir: 'using', title: 'Using Extrovert' },
  { dir: 'developers', title: 'Developers' },
];

function buildNav() {
  const nav = [];
  for (const group of GROUPS) {
    const dirPath = path.join(DOCS_ROOT, group.dir);
    let files = [];
    try {
      files = fs.readdirSync(dirPath).filter(f => f.toLowerCase().endsWith('.md')).sort();
    } catch {
      continue;
    }
    const pages = files.map((file) => {
      const source = fs.readFileSync(path.join(dirPath, file), 'utf8');
      const relPath = group.dir ? group.dir + '/' + file : file;
      return {
        url: '/' + relPath.toLowerCase().replace(/\.md$/, ''),
        title: titleFromSource(source, file.replace(/\.md$/i, '')),
      };
    });
    nav.push({ title: group.title, pages });
  }
  return nav;
}

const NAV = buildNav();

// ---- Serving ----

// Only files under docs/ are served, plus two explicit repo-root allowlist
// exceptions (README/LICENSE, linked from the wiki). Anything else — the
// database, key material, mail spool, dotfiles — must never be reachable.
const ROOT_ALLOWLIST = new Set(['README.md', 'LICENSE']);

function resolveFile(rel) {
  // Reject dotfiles/dot-directories (.env, .git/config, …) outright.
  if (rel.split('/').some(seg => seg.startsWith('.'))) return null;

  const allowlisted = ROOT_ALLOWLIST.has(rel) || ROOT_ALLOWLIST.has(rel + '.md');
  const resolved = path.resolve(DOCS_ROOT, rel);
  const inDocs = resolved === DOCS_ROOT || resolved.startsWith(DOCS_ROOT + path.sep);

  if (!inDocs && !allowlisted) return null;

  const candidates = rel.toLowerCase().endsWith('.md')
    ? [resolved]
    : [resolved + '.md', resolved];
  if (allowlisted) {
    candidates.push(path.join(REPO_ROOT, rel), path.join(REPO_ROOT, rel + '.md'));
  }
  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
}

function findNavEntry(rel) {
  const url = '/' + rel.toLowerCase().replace(/\.md$/, '');
  for (const group of NAV) {
    const found = group.pages.find(p => p.url === url);
    if (found) return { group, page: found };
  }
  return null;
}

router.get('/*', (req, res) => {
  const rel = (req.path || '').replace(/^\/+/, '');
  const relFile = rel === '' ? 'README.md' : rel;

  if (rel.split('/').includes('..')) return res.status(404).render('404', { thing: 'page' });

  const file = resolveFile(relFile);
  if (!file) return res.status(404).render('404', { thing: 'page' });

  let source;
  try {
    source = fs.readFileSync(file, 'utf8');
  } catch {
    return res.status(404).render('404', { thing: 'page' });
  }

  const relDir = relFile === 'README.md' || !relFile.includes('/') ? '' : path.posix.dirname(relFile);
  const contentHtml = md.render(source, { relDir });
  const currentUrl = (relFile === 'README.md' ? '/' : '/' + relFile).toLowerCase().replace(/\.md$/, '');
  const entry = findNavEntry(relFile === 'README.md' ? 'README.md' : rel);

  res.render('docs', {
    wrapClass: 'docs-wrap',
    pageTitle: titleFromSource(source, relFile.replace(/\.md$/i, '')),
    contentHtml,
    nav: NAV,
    currentUrl,
    currentGroup: entry ? entry.group.title : null,
    currentPageTitle: entry ? entry.page.title : null,
  });
});

module.exports = router;
