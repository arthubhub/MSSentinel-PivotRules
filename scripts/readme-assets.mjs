#!/usr/bin/env node
// README visuals generated from dist/pivot-rules.json (run `npm run build` first):
//   docs/matrix-<lang>.svg   cross-pivot heatmap (start type x target type, Pivot/Timeline rules)
//   docs/coverage-<lang>.svg rules per indicator type, split by action
import fs from 'node:fs';
const root = new URL('..', import.meta.url).pathname;
const c = JSON.parse(fs.readFileSync(`${root}dist/pivot-rules.json`, 'utf8'));
const kinds = Object.keys(c.indicators);
const L = {
  en: { ip: 'IP', account: 'Account', email: 'E-mail', url: 'URL', domain: 'Domain', device: 'Device', process: 'Process', application: 'App', hash: 'Hash',
    from: 'start ↓  target →', title: 'Cross pivots: rules from one indicator type to another', stats: 'Statistics', pivot: 'Pivot', timeline: 'Timeline',
    cov: 'Rules per indicator type' },
  fr: { ip: 'IP', account: 'Compte', email: 'E-mail', url: 'URL', domain: 'Domaine', device: 'Machine', process: 'Processus', application: 'Appli', hash: 'Hash',
    from: 'départ ↓  cible →', title: "Pivots croisés : règles d'un type d'indicateur vers un autre", stats: 'Statistics', pivot: 'Pivot', timeline: 'Timeline',
    cov: "Règles par type d'indicateur" },
};
const esc = (s) => String(s).replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[ch]);
const font = 'font-family="Segoe UI, Inter, Helvetica, Arial, sans-serif"';

function matrix(lang) {
  const t = L[lang];
  const cell = 64, left = 130, top = 120, n = kinds.length;
  const count = (from, to) => c.rules.filter((r) => r.action !== 'statistics' && r.indicators.includes(from) && (r.targets || []).includes(to)).length;
  const max = Math.max(1, ...kinds.flatMap((f) => kinds.map((to) => (f === to ? 0 : count(f, to)))));
  const w = left + n * cell + 40, h = top + n * cell + 40;
  const out = [`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" ${font}>`,
    `<rect width="${w}" height="${h}" rx="16" fill="#101626"/>`,
    `<text x="24" y="40" font-size="20" font-weight="700" fill="#ffffff">${esc(t.title)}</text>`,
    `<text x="24" y="${top - 16}" font-size="12" fill="#7f93b8">${esc(t.from)}</text>`];
  kinds.forEach((k, i) => {
    out.push(`<text x="${left + i * cell + cell / 2}" y="${top - 12}" font-size="13" fill="#b9c7e6" text-anchor="middle">${esc(t[k])}</text>`);
    out.push(`<text x="${left - 12}" y="${top + i * cell + cell / 2 + 5}" font-size="13" fill="#b9c7e6" text-anchor="end">${esc(t[k])}</text>`);
  });
  kinds.forEach((f, i) => kinds.forEach((to, j) => {
    const x = left + j * cell, y = top + i * cell;
    if (f === to) { out.push(`<rect x="${x + 3}" y="${y + 3}" width="${cell - 6}" height="${cell - 6}" rx="8" fill="#1a2238"/>`); return; }
    const v = count(f, to);
    const a = v === 0 ? 0 : 0.25 + 0.75 * (v / max);
    out.push(`<rect x="${x + 3}" y="${y + 3}" width="${cell - 6}" height="${cell - 6}" rx="8" fill="${v ? `rgba(79,139,255,${a.toFixed(2)})` : '#161d30'}" stroke="#24304d"/>`);
    if (v) out.push(`<text x="${x + cell / 2}" y="${y + cell / 2 + 6}" font-size="17" font-weight="700" fill="#ffffff" text-anchor="middle">${v}</text>`);
  }));
  out.push('</svg>');
  return out.join('\n');
}

function coverage(lang) {
  const t = L[lang];
  const acts = [['statistics', '#8764b8'], ['pivot', '#4f8bff'], ['timeline', '#e8833a']];
  // Domain rules also take URLs: one "Domain / URL" row
  const rows = kinds.filter((k) => k !== 'url').map((k) => ({ k, v: acts.map(([a]) => c.rules.filter((r) => r.indicators[0] === k && r.action === a).length) }));
  const max = Math.max(...rows.map((r) => r.v.reduce((s, x) => s + x, 0)));
  const left = 150, top = 80, bar = 30, gap = 12, scale = 560 / max;
  const w = left + 620 + 40, h = top + rows.length * (bar + gap) + 30;
  const out = [`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" ${font}>`,
    `<rect width="${w}" height="${h}" rx="16" fill="#101626"/>`,
    `<text x="24" y="40" font-size="20" font-weight="700" fill="#ffffff">${esc(t.cov)}</text>`];
  acts.forEach(([a, col], i) => {
    out.push(`<rect x="${left + i * 130}" y="54" width="14" height="14" rx="3" fill="${col}"/><text x="${left + i * 130 + 20}" y="66" font-size="13" fill="#b9c7e6">${esc(t[a === 'statistics' ? 'stats' : a])}</text>`);
  });
  rows.forEach((r, i) => {
    const y = top + i * (bar + gap);
    const label = r.k === 'domain' ? `${t.domain} / ${t.url}` : t[r.k];
    out.push(`<text x="${left - 12}" y="${y + bar / 2 + 5}" font-size="14" fill="#b9c7e6" text-anchor="end">${esc(label)}</text>`);
    let x = left;
    r.v.forEach((v, j) => { if (!v) return; const wd = v * scale; out.push(`<rect x="${x}" y="${y}" width="${wd - 2}" height="${bar}" rx="5" fill="${acts[j][1]}"/>`); if (wd > 22) out.push(`<text x="${x + wd / 2 - 1}" y="${y + bar / 2 + 5}" font-size="13" font-weight="700" fill="#ffffff" text-anchor="middle">${v}</text>`); x += wd; });
  });
  out.push('</svg>');
  return out.join('\n');
}

fs.mkdirSync(`${root}docs`, { recursive: true });
for (const lang of ['en', 'fr']) {
  fs.writeFileSync(`${root}docs/matrix-${lang}.svg`, matrix(lang) + '\n');
  fs.writeFileSync(`${root}docs/coverage-${lang}.svg`, coverage(lang) + '\n');
}
console.log(`readme-assets: ${c.rules.length} rules, ${(c.scenarios || []).length} scenarios -> docs/matrix-*.svg, docs/coverage-*.svg`);
