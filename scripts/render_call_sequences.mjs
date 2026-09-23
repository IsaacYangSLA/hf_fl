#!/usr/bin/env node
// Render local Mermaid sources into SVGs and one offline HTML document.
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: {
  mermaid: { type: 'string' }, puppeteer: { type: 'string' },
  browser: { type: 'string' }, 'no-sandbox': { type: 'boolean', default: false },
} });
if (!values.mermaid || !values.puppeteer || !values.browser) {
  throw new Error('Required: --mermaid /path/mermaid.min.js --puppeteer /path/puppeteer-core --browser /path/chrome');
}
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = join(root, 'docs', 'diagrams');
const diagrams = [
  { id: 'upload', file: 'exchange-upload', title: 'Upload & publish',
    description: 'Small metadata requests go to the service. Large files go directly to private blob storage. The worker verifies each stored version before the client publishes its record.' },
  { id: 'download', file: 'exchange-download', title: 'Read & download',
    description: 'The service checks current access and returns metadata or a short-lived download grant. The client reads the pinned object version directly and verifies the downloaded bytes.' },
  { id: 'fedavg', file: 'fedavg-round', title: 'Federated round',
    description: 'Two participants train from one immutable global base. The owner freezes eligible updates, validates and averages them, then advances main through a fenced acquisition.' },
];
const puppeteer = createRequire(import.meta.url)(resolve(values.puppeteer));
const profile = await mkdtemp(join(tmpdir(), 'hf2l-mermaid-'));
let browser;
try {
  browser = await puppeteer.launch({
    executablePath: resolve(values.browser), headless: true, userDataDir: profile,
    args: ['--disable-dev-shm-usage', ...(values['no-sandbox'] ? ['--no-sandbox'] : [])],
  });
  const page = await browser.newPage();
  await page.setOfflineMode(true);
  await page.setViewport({ width: 1600, height: 1000, deviceScaleFactor: 1 });
  await page.setContent('<!doctype html><html><head><meta charset="utf-8"></head><body></body></html>');
  await page.addScriptTag({ path: resolve(values.mermaid) });
  await page.evaluate(() => mermaid.initialize({
    startOnLoad: false, securityLevel: 'strict', theme: 'base',
    deterministicIds: true, deterministicIDSeed: 'hf2l-call-sequences',
    fontFamily: 'Arial, sans-serif',
    themeVariables: {
      primaryColor: '#eaf1fa', primaryTextColor: '#152d4a', primaryBorderColor: '#7998bd',
      lineColor: '#42658c', actorBkg: '#eaf1fa', actorBorder: '#7998bd',
      actorTextColor: '#152d4a', signalColor: '#42658c', signalTextColor: '#152d4a',
      noteBkgColor: '#f3f7ed', noteBorderColor: '#b2c69b', noteTextColor: '#314327',
      labelBoxBkgColor: '#f0f4f9', labelBoxBorderColor: '#7998bd', labelTextColor: '#152d4a',
    },
    sequence: { useMaxWidth: false, wrap: true, width: 180, actorMargin: 40,
      messageMargin: 32, noteMargin: 16, diagramMarginX: 24, diagramMarginY: 20,
      mirrorActors: true },
  }));
  for (const diagram of diagrams) {
    diagram.source = await readFile(join(output, `${diagram.file}.mmd`), 'utf8');
    diagram.svg = await page.evaluate(async ({ id, source }) => {
      await mermaid.parse(source);
      return (await mermaid.render(`sequence-${id}`, source)).svg;
    }, diagram);
    // Mermaid sequence marker IDs can repeat across SVGs. Namespace every ID
    // before embedding multiple diagrams in the same HTML document.
    const ids = [...new Set([...diagram.svg.matchAll(/\sid="([^"]+)"/g)].map(match => match[1]))];
    for (const id of ids.sort((a, b) => b.length - a.length)) {
      const replacement = `${diagram.id}-${id}`;
      diagram.svg = diagram.svg.replaceAll(`id="${id}"`, `id="${replacement}"`)
        .replaceAll(`url(#${id})`, `url(#${replacement})`)
        .replaceAll(`href="#${id}"`, `href="#${replacement}"`)
        .replaceAll(`aria-labelledby="${id}"`, `aria-labelledby="${replacement}"`)
        .replaceAll(`aria-describedby="${id}"`, `aria-describedby="${replacement}"`);
      // Scoped SVG styles refer to the diagram's root ID.
      diagram.svg = diagram.svg.replaceAll(`#${id}{`, `#${replacement}{`)
        .replaceAll(`#${id} `, `#${replacement} `);
    }
    // Mirrored actor decorations may repeat IDs within a single Mermaid SVG.
    const occurrences = new Map();
    diagram.svg = diagram.svg.replace(/\sid="([^"]+)"/g, (attribute, id) => {
      const count = occurrences.get(id) || 0;
      occurrences.set(id, count + 1);
      return count ? ` id="${id}-${count}"` : attribute;
    });
    await writeFile(join(output, `${diagram.file}.svg`), `${diagram.svg}\n`);
  }
} finally {
  if (browser) await browser.close();
  await rm(profile, { recursive: true, force: true });
}

const escape = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const panels = diagrams.map(diagram => `
<section class="panel" id="${diagram.id}" aria-labelledby="heading-${diagram.id}">
  <div class="panel-heading"><div><p class="eyebrow">CALL SEQUENCE / ${diagram.id.toUpperCase()}</p>
    <h2 id="heading-${diagram.id}">${escape(diagram.title)}</h2>
    <p>${escape(diagram.description)}</p></div></div>
  <div class="toolbar" aria-label="Diagram controls">
    <button type="button" data-action="fit">Fit width</button>
    <button type="button" data-action="actual">100%</button>
    <button type="button" data-action="out" aria-label="Zoom out">−</button>
    <button type="button" data-action="in" aria-label="Zoom in">+</button>
    <output aria-live="polite">100%</output>
    <button type="button" data-action="svg">Save SVG</button>
  </div>
  <div class="viewport" tabindex="0" aria-label="${escape(diagram.title)} sequence diagram; scroll to explore">${diagram.svg}</div>
  <details><summary>Mermaid source</summary><pre><code>${escape(diagram.source)}</code></pre></details>
</section>`).join('\n');

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>HF²L · Call sequences</title>
<style>
:root{font-family:Arial,sans-serif;color:#162c46;background:#f2f5f9;color-scheme:light}
*{box-sizing:border-box}body{margin:0}header{background:#142b46;color:#fff;padding:32px max(24px,calc((100vw - 1440px)/2)) 28px}
.eyebrow{font-size:11px;font-weight:700;letter-spacing:.14em;margin:0 0 12px;color:#607c99}header .eyebrow{color:#acbfd5}
h1{font-size:32px;letter-spacing:-.025em;margin:0 0 12px}header p{color:#d6e1ef;line-height:1.6;max-width:880px;margin:0}
main{max-width:1488px;margin:auto;padding:24px}nav{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 20px}
nav a,button{font:inherit;font-size:14px;border:1px solid #c5d2e1;border-radius:6px;background:#fff;color:#254a74;padding:9px 14px;text-decoration:none;cursor:pointer}
nav a[aria-current="page"]{background:#234f7e;border-color:#234f7e;color:white}button:hover,nav a:hover{background:#eaf1fa;color:#162c46}
a:focus-visible,button:focus-visible,summary:focus-visible,.viewport:focus-visible{outline:3px solid #2a80cb;outline-offset:3px}
.panel{border:1px solid #d6e0ec;border-radius:10px;background:#fff;margin-bottom:24px;overflow:hidden}.panel[hidden]{display:none}
.panel-heading{padding:24px 24px 16px}.panel-heading h2{font-size:23px;margin:0 0 10px}.panel-heading p:last-child{line-height:1.55;max-width:1050px;color:#50647d;margin:0}
.toolbar{display:none;align-items:center;flex-wrap:wrap;gap:8px;padding:12px 24px;background:#f8fafd;border-block:1px solid #e2e9f1}.js .toolbar{display:flex}
output{font-size:13px;color:#526880;min-width:52px}.viewport{overflow:auto;max-height:72vh;padding:20px;background:white;overscroll-behavior:contain}
.viewport svg{display:block;max-width:100%;height:auto;margin:auto}.js .viewport svg{max-width:none}
details{border-top:1px solid #e2e9f1;padding:16px 24px}summary{cursor:pointer;color:#254a74;font-weight:600;font-size:14px}
pre{overflow:auto;font-size:12px;line-height:1.6;color:#33465f;background:#f5f7fa;padding:18px;border-radius:6px;max-height:440px}
.context{display:grid;grid-template-columns:1fr 1fr;gap:28px;font-size:14px;line-height:1.65;color:#50647d}.context h3{font-size:14px;color:#162c46;margin:0 0 6px}.context p{margin:0}
a{color:#255c93}footer{font-size:12px;color:#61738b;margin-top:22px;padding-top:16px;border-top:1px solid #d6e0ec}
@media(max-width:640px){header{padding:24px}h1{font-size:27px}main{padding:16px}.panel-heading{padding:20px}.context{grid-template-columns:1fr;gap:18px}.viewport{padding:10px}}
@media print{header{background:white;color:#162c46;padding:0 0 16px}header p{color:#50647d}main{max-width:none;padding:0}nav,.toolbar,details{display:none!important}.panel,.panel[hidden]{display:block;break-before:page;border:none}.panel-heading{padding:16px 0}.viewport{max-height:none;overflow:visible;padding:0}.viewport svg{width:100%!important;max-width:100%!important}.context{display:block}.context>div{margin-top:16px}footer{break-inside:avoid}}
</style></head><body>
<header><p class="eyebrow">HF²L / ARCHITECTURE V3 · EXCHANGE API V2</p><h1>From metadata to model publication</h1>
<p>Call sequences traced from the current implementation. Follow the generic file exchange first, then see how federated learning uses the same service and storage.</p></header>
<main><nav aria-label="Choose a call sequence">${diagrams.map(d => `<a href="#${d.id}">${escape(d.title)}</a>`).join('')}</nav>
${panels}
<div class="context"><div><h3>Reading the diagrams</h3><p>Solid arrows are calls; dashed arrows are responses. Notes group prerequisites and intentional omissions. Routes are relative to the space prefix identified in each diagram. The API lane includes authentication, transactional application commands, and transfer orchestration.</p></div>
<div><h3>Scope and current limitations</h3><p>These views cover the independent Exchange backend and a successful owner-controlled FedAvg round. Identity provisioning, HF/JFrog transports, and failure/cleanup paths are outside this view. Existing implementation gaps remain: see the <a href="../ARCHITECTURE_V3.md#current-implementation-limitations">v3 limitations</a> and <a href="../EXCHANGE_V3.md">service runbook</a>.</p></div></div>
<footer>Rendered from editable Mermaid sources. All diagrams and source text are embedded; this page makes no network requests. <a href="README.md">Source map and regeneration instructions</a>.</footer>
</main>
<script>
document.documentElement.classList.add('js');
const panels = [...document.querySelectorAll('.panel')];
const scales = new Map();
function zoom(panel, value) {
  const svg = panel.querySelector('svg');
  const scale = Math.min(3, Math.max(0.15, value));
  scales.set(panel.id, scale);
  svg.style.width = (svg.viewBox.baseVal.width * scale) + 'px';
  panel.querySelector('output').textContent = Math.round(scale * 100) + '%';
}
function fit(panel) {
  const viewport = panel.querySelector('.viewport');
  const style = getComputedStyle(viewport);
  const space = viewport.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
  zoom(panel, Math.min(1, space / panel.querySelector('svg').viewBox.baseVal.width));
}
function select() {
  const selected = panels.find(panel => '#' + panel.id === location.hash) || panels[0];
  panels.forEach(panel => { panel.hidden = panel !== selected; });
  document.querySelectorAll('nav a').forEach(link => {
    if (link.hash === '#' + selected.id) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  if (!scales.has(selected.id)) fit(selected);
}
document.querySelectorAll('[data-action]').forEach(button => button.addEventListener('click', () => {
  const panel = button.closest('.panel');
  const action = button.dataset.action;
  if (action === 'fit') fit(panel);
  else if (action === 'actual') zoom(panel, 1);
  else if (action === 'in' || action === 'out') zoom(panel, scales.get(panel.id) * (action === 'in' ? 1.25 : 0.8));
  else if (action === 'svg') {
    const svg = panel.querySelector('svg').cloneNode(true);
    svg.style.removeProperty('width');
    const url = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(svg)], {type:'image/svg+xml'}));
    const link = document.createElement('a'); link.href = url; link.download = panel.id + '.svg';
    document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}));
window.addEventListener('hashchange', select);
select();
</script></body></html>
`;
await writeFile(join(output, 'call-sequences.html'), html);
console.log(`Rendered ${diagrams.length} Mermaid diagrams into docs/diagrams/call-sequences.html`);
