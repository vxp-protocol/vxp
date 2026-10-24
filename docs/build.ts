// Builds the documentation site from docs/*.md into site/docs/, plus site/llms.txt and site/llms-full.txt.
//
// The Markdown in docs/ is the only source. Each page is also published as Markdown next to its HTML
// (site/docs/<slug>.md), for agents and for reuse. Rule references written as [[R6]] or [[native-only|text]]
// link to the canonical specification and must exist in spec/spec.tpl.html, or the build fails. Captured
// objects are inserted with <!--json:step.path-->, read from site/assets/recorrido-data.js, so examples are
// what the reference implementation actually produced.
//
// Usage, from the repository root: node docs/build.ts

import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";

const RAIZ = join(import.meta.dirname, "..");
const SITE = join(RAIZ, "site");
const OUT = join(SITE, "docs");
const URL_BASE = "https://vxpprotocol.org";
const nav = JSON.parse(readFileSync(join(import.meta.dirname, "nav.json"), "utf8")) as { version: string; sections: { title: string; pages: { slug: string; file: string }[] }[] };
const spec = readFileSync(join(RAIZ, "spec", "spec.tpl.html"), "utf8");
const idsSpec = new Set([...spec.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
const datos = (() => {
	const s = readFileSync(join(SITE, "assets", "recorrido-data.js"), "utf8");
	return JSON.parse(s.slice(s.indexOf("{"), s.lastIndexOf("}") + 1));
})();
const errores: string[] = [];

type Pagina = { slug: string; file: string; title: string; description: string; md: string; html: string; toc: { id: string; text: string; level: number }[]; text: string };

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const slugify = (s: string) => s.toLowerCase().replace(/<[^>]+>/g, "").replace(/`/g, "").replace(/[^a-z0-9\s-]/g, "").trim().replace(/\s+/g, "-").replace(/-+/g, "-");
const profundidad = (slug: string) => (slug === "" ? 1 : slug.split("/").length + 1);
const raiz = (slug: string) => "../".repeat(profundidad(slug));

function frontMatter(src: string) {
	const m = src.match(/^---\n([\s\S]*?)\n---\n/);
	const meta: Record<string, string> = {};
	if (m) for (const l of m[1].split("\n")) { const i = l.indexOf(":"); if (i > 0) meta[l.slice(0, i).trim()] = l.slice(i + 1).trim(); }
	return { meta, body: m ? src.slice(m[0].length) : src };
}

/** A value captured from the reference implementation: step id, then a dotted path inside that step. */
function capturado(ref: string): unknown {
	const [paso, ...ruta] = ref.split(".");
	let v: any = datos.steps.find((s: { id: string }) => s.id === paso);
	for (const k of ruta) v = v?.[k];
	if (v === undefined) errores.push(`json:${ref} not found in recorrido-data.js`);
	return v;
}

/** [[R6]], [[P5]], [[native-only|Native-only gateway]], [[§8 native-only]] → link into the specification. */
function reglas(s: string, slug: string, absoluto: boolean) {
	return s.replace(/\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g, (_, ref: string, texto?: string) => {
		const ancla = /^[A-Za-z]{1,2}\d+$/.test(ref) ? ref.toLowerCase() : ref.trim();
		if (!idsSpec.has(ancla)) errores.push(`${slug || "index"}: [[${ref}]] has no anchor #${ancla} in the specification`);
		const href = `${absoluto ? `${URL_BASE}/` : raiz(slug)}spec/#${ancla}`;
		const etiqueta = texto ?? (/^[A-Za-z]{1,2}\d+$/.test(ref) ? ref.toUpperCase() : ref);
		return absoluto ? `[${etiqueta}](${href})` : `<a class="rule" href="${href}">${esc(etiqueta)}</a>`;
	});
}

/** Relative .md links between docs pages become links to their HTML pages (or absolute URLs for .md output). */
function enlaces(href: string, slug: string, absoluto: boolean) {
	const m = href.match(/^((?:\.\/|\.\.\/)*[a-z0-9/-]+)\.md(#.*)?$/);
	if (m) {
		// Resolved from the folder of the page that links, like any relative link in Markdown.
		const carpeta = slug.includes("/") ? slug.slice(0, slug.lastIndexOf("/")) : "";
		const ruta = posix.normalize(posix.join(carpeta, m[1]));
		const destino = ruta === "index" ? "" : ruta;
		if (!todas.some((p) => p.slug === destino)) errores.push(`${slug || "index"}: link to missing page ${href}`);
		return absoluto ? `${URL_BASE}/docs/${destino}${destino ? "/" : ""}${m[2] ?? ""}` : `${raiz(slug)}docs/${destino}${destino ? "/" : ""}${m[2] ?? ""}`;
	}
	if (href.startsWith("/")) return absoluto ? `${URL_BASE}${href}` : `${raiz(slug)}${href.slice(1)}`;
	return href;
}

function inline(s: string, slug: string) {
	const codes: string[] = [];
	s = s.replace(/`([^`]+)`/g, (_, c) => `\u0000${codes.push(esc(c)) - 1}\u0000`);
	s = esc(s).replace(/&lt;br&gt;/g, "<br>");
	s = reglas(s, slug, false);
	s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, t, h) => `<a href="${enlaces(h, slug, false)}">${t}</a>`);
	s = s.replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<em>$2</em>");
	return s.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${codes[Number(i)]}</code>`);
}

function markdownAHtml(md: string, slug: string) {
	const lineas = md.split("\n");
	const out: string[] = [];
	const toc: Pagina["toc"] = [];
	const usados = new Set<string>();
	let i = 0;
	const parrafo: string[] = [];
	const cerrarParrafo = () => {
		if (parrafo.length) out.push(`<p>${inline(parrafo.join(" "), slug)}</p>`);
		parrafo.length = 0;
	};
	while (i < lineas.length) {
		const l = lineas[i];
		const json = l.match(/^<!--json:([\w.]+)(?:\s+title="([^"]*)")?-->$/);
		if (json) {
			cerrarParrafo();
			const v = capturado(json[1]);
			out.push(`<div class="code"><div class="code__head"><b>${esc(json[2] ?? json[1])}</b><span>captured from the reference implementation</span></div><pre data-copy tabindex="0">${esc(JSON.stringify(v, null, 2))}</pre></div>`);
			i++;
			continue;
		}
		const fence = l.match(/^```(\w*)(?:\s+title="([^"]*)")?\s*$/);
		if (fence) {
			cerrarParrafo();
			const cuerpo: string[] = [];
			i++;
			while (i < lineas.length && !/^```\s*$/.test(lineas[i])) cuerpo.push(lineas[i++]);
			i++;
			out.push(`<div class="code"><div class="code__head"><b>${esc(fence[2] ?? fence[1] ?? "")}</b><span>${esc(fence[1] || "text")}</span></div><pre data-copy tabindex="0">${esc(cuerpo.join("\n"))}</pre></div>`);
			continue;
		}
		const h = l.match(/^(#{2,4})\s+(.*)$/);
		if (h) {
			cerrarParrafo();
			const nivel = h[1].length;
			const explicito = h[2].match(/\{#([a-z0-9-]+)\}\s*$/);
			const texto = h[2].replace(/\s*\{#[a-z0-9-]+\}\s*$/, "");
			let id = explicito?.[1] ?? slugify(texto);
			while (usados.has(id)) id += "-2";
			usados.add(id);
			if (nivel <= 3) toc.push({ id, text: texto.replace(/`/g, ""), level: nivel });
			out.push(`<h${nivel} id="${id}">${inline(texto, slug)}<a class="anchor" href="#${id}" aria-label="Link to ${esc(texto.replace(/`/g, ""))}">#</a></h${nivel}>`);
			i++;
			continue;
		}
		if (/^\|/.test(l)) {
			cerrarParrafo();
			const filas: string[] = [];
			while (i < lineas.length && /^\|/.test(lineas[i])) filas.push(lineas[i++]);
			const celdas = (f: string) => f.replace(/^\||\|$/g, "").split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|"));
			const cab = celdas(filas[0]);
			const cuerpo = filas.slice(2).map(celdas);
			out.push(`<div class="tbl tbl--fit"><table><thead><tr>${cab.map((c) => `<th>${inline(c, slug)}</th>`).join("")}</tr></thead><tbody>${cuerpo.map((r) => `<tr>${r.map((c) => `<td>${inline(c, slug)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`);
			continue;
		}
		if (/^>\s?/.test(l)) {
			cerrarParrafo();
			const bloque: string[] = [];
			while (i < lineas.length && /^>\s?/.test(lineas[i])) bloque.push(lineas[i++].replace(/^>\s?/, ""));
			out.push(`<div class="callout"><p>${inline(bloque.join(" "), slug)}</p></div>`);
			continue;
		}
		const li = l.match(/^(\s*)(-|\d+\.)\s+(.*)$/);
		if (li) {
			cerrarParrafo();
			const ordenada = /\d/.test(li[2]);
			const items: string[] = [];
			while (i < lineas.length) {
				const x = lineas[i].match(/^(\s*)(-|\d+\.)\s+(.*)$/);
				if (x) items.push(x[3]);
				else if (/^\s{2,}\S/.test(lineas[i]) && items.length) items[items.length - 1] += " " + lineas[i].trim();
				else break;
				i++;
			}
			out.push(`<${ordenada ? "ol" : "ul"}>${items.map((x) => `<li>${inline(x, slug)}</li>`).join("")}</${ordenada ? "ol" : "ul"}>`);
			continue;
		}
		if (!l.trim()) {
			cerrarParrafo();
			i++;
			continue;
		}
		parrafo.push(l.trim());
		i++;
	}
	cerrarParrafo();
	return { html: out.join("\n"), toc };
}

/** The Markdown published next to each page: rule references and page links become absolute URLs. */
function markdownPublicado(p: Pagina) {
	let s = reglas(p.md, p.slug, true);
	s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, t, h) => `[${t}](${enlaces(h, p.slug, true)})`);
	s = s.replace(/^<!--json:([\w.]+)(?:\s+title="([^"]*)")?-->$/gm, (_, ref) => "```json\n" + JSON.stringify(capturado(ref), null, 2) + "\n```");
	return `# ${p.title}\n\n> ${p.description}\n\n${s.trim()}\n`;
}

// ── Pages ───────────────────────────────────────────────────────────────────────────────────────
const todas: Pagina[] = [];
for (const sec of nav.sections)
	for (const pg of sec.pages) {
		// "@FILE.md" pages are files of the repository root (the changelog), published as they are.
		const src = pg.file.startsWith("@")
			? "---\ntitle: Changelog\ndescription: Every notable change to the specification and the repository, by version.\n---\n" + readFileSync(join(RAIZ, pg.file.slice(1)), "utf8").replace(/\r\n/g, "\n").replace(/^# .*\n/, "")
			: readFileSync(join(import.meta.dirname, pg.file), "utf8").replace(/\r\n/g, "\n");
		const { meta, body } = frontMatter(src);
		if (!meta.title || !meta.description) errores.push(`${pg.file}: front matter needs title and description`);
		todas.push({ slug: pg.slug, file: pg.file, title: meta.title, description: meta.description, md: body, html: "", toc: [], text: "" });
	}
for (const p of todas) {
	const r = markdownAHtml(p.md, p.slug);
	p.html = r.html;
	p.toc = r.toc;
	p.text = p.md.replace(/```[\s\S]*?```/g, " ").replace(/<!--[\s\S]*?-->/g, " ").replace(/\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g, "$2 $1").replace(/[#*`>|[\]()]/g, " ").replace(/\s+/g, " ").trim();
}

function pagina(p: Pagina) {
	const r = raiz(p.slug);
	const navHtml = nav.sections
		.map((s) => `<div class="dnav__sec"><p class="dnav__h">${esc(s.title)}</p><ul>${s.pages.map((x) => {
			const t = todas.find((y) => y.slug === x.slug)!;
			return `<li><a href="${r}docs/${x.slug}${x.slug ? "/" : ""}"${x.slug === p.slug ? ' aria-current="page"' : ""}>${esc(t.title)}</a></li>`;
		}).join("")}</ul></div>`)
		.join("");
	const enPagina = p.toc.filter((t) => t.level === 2);
	const idx = todas.indexOf(p);
	const ant = todas[idx - 1];
	const sig = todas[idx + 1];
	const href = (x: Pagina) => `${r}docs/${x.slug}${x.slug ? "/" : ""}`;
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(p.title)} · VXP docs</title>
<meta name="description" content="${esc(p.description)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="VXP">
<meta property="og:title" content="${esc(p.title)} · VXP docs">
<meta property="og:description" content="${esc(p.description)}">
<meta property="og:url" content="https://vxpprotocol.org/docs/${p.slug ? p.slug + "/" : ""}">
<meta property="og:locale" content="en_US">
<meta property="og:image" content="https://vxpprotocol.org/assets/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="VXP, Verifiable eXchange Protocol: an open protocol for the work personal agents do for people inside companies.">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="/favicon.ico?v=2" sizes="48x48">
<link rel="icon" type="image/png" sizes="192x192" href="/assets/icon-192.png">
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
<link rel="alternate" type="text/markdown" href="${r}docs/${p.slug || "index"}.md">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="${r}assets/vxp.css">
<link rel="stylesheet" href="${r}assets/docs.css">
<link rel="stylesheet" href="${r}assets/docs-site.css">
<script>document.documentElement.classList.add("js")</script>
</head>
<body data-root="${r}">
<a class="skip" href="#main">Skip to content</a>
<header class="nav">
	<div class="nav__in">
		<a class="mark" href="${r}"><b>VXP</b><span>Verifiable eXchange Protocol</span></a>
		<button class="nav__menu" type="button" aria-expanded="false" aria-controls="menu">Menu</button>
		<ul id="menu">
			<li><a href="${r}docs/" aria-current="page">Docs</a></li>
			<li><a href="${r}architecture/">Architecture</a></li>
			<li><a href="${r}spec/">Specification</a></li>
			<li><a href="${r}examples/">Examples</a></li>
			<li><a href="${r}verify/">Verify</a></li>
			<li><a href="${r}conformance/">Conformance</a></li>
			<li><a href="${r}implement/">Implement</a></li>
			<li><a href="${r}demos/">Demos</a></li>
		</ul>
		<a class="nav__ver" href="${r}status/">Draft ${esc(nav.version)}</a>
	</div>
</header>
<div class="dlay">
<aside class="dnav" aria-label="Documentation">
	<div class="dsearch" role="search">
		<label class="sr" for="dsearch-q">Search the docs</label>
		<input id="dsearch-q" type="search" placeholder="Search the docs" autocomplete="off" aria-controls="dsearch-r">
		<ul id="dsearch-r" class="dsearch__r" hidden></ul>
	</div>
	<details class="dnav__wrap" open>
		<summary>Documentation</summary>
		${navHtml}
	</details>
</aside>
<main id="main" class="dmain">
	<article class="dsec dpage">
		<p class="kicker">VXP docs · draft ${esc(nav.version)}</p>
		<h1 class="h2">${esc(p.title)}</h1>
		<p class="lead">${inline(p.description, p.slug)}</p>
		${enPagina.length > 2 ? `<nav class="dontoc" aria-label="On this page"><p>On this page</p><ul>${enPagina.map((t) => `<li><a href="#${t.id}">${esc(t.text)}</a></li>`).join("")}</ul></nav>` : ""}
		${p.html}
		<div class="dfoot">
			<a href="${r}docs/${p.slug || "index"}.md">View as Markdown</a>
			<a href="https://github.com/vxp-protocol/vxp/blob/main/${p.file.startsWith("@") ? p.file.slice(1) : `docs/${p.file}`}">Source</a>
		</div>
		<nav class="dprevnext" aria-label="Previous and next">
			${ant ? `<a href="${href(ant)}"><span>Previous</span>${esc(ant.title)}</a>` : "<span></span>"}
			${sig ? `<a href="${href(sig)}"><span>Next</span>${esc(sig.title)}</a>` : "<span></span>"}
		</nav>
	</article>
</main>
</div>
<footer class="foot">
	<div class="foot__in">
		<div><b>VXP</b><p style="margin-top:8px;max-width:44ch">An open protocol, developed by SOVRAS. Anyone can implement it; the specification, reference implementation and tools are Apache 2.0.</p></div>
		<div><b>Docs</b><ul><li><a href="${r}docs/quickstart/">Quickstart</a></li><li><a href="${r}spec/">Specification</a></li><li><a href="${r}llms.txt">llms.txt</a></li></ul></div>
		<div><b>Tools</b><ul><li><a href="${r}verify/">Verifier</a></li><li><a href="${r}demos/">Demos</a></li><li><a href="${r}conformance/">Conformance</a></li></ul></div>
		<div><b>Project</b><ul><li><a href="https://github.com/vxp-protocol/vxp">Repository</a></li><li><a href="${r}docs/changelog/">Changelog</a></li><li><a href="${r}status/">Status</a></li></ul></div>
	</div>
</footer>
<script src="${r}assets/site.js" defer></script>
<script src="${r}assets/docs-site.js" defer></script>
</body>
</html>
`;
}

rmSync(OUT, { recursive: true, force: true });
for (const p of todas) {
	const dir = p.slug ? join(OUT, p.slug) : OUT;
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, "index.html"), pagina(p));
	const md = join(OUT, `${p.slug || "index"}.md`);
	mkdirSync(dirname(md), { recursive: true });
	writeFileSync(md, markdownPublicado(p));
}
// Search index: page, headings and text, for the client-side search.
writeFileSync(join(OUT, "search-index.json"), JSON.stringify(todas.map((p) => ({ slug: p.slug, title: p.title, description: p.description, headings: p.toc.map((t) => ({ id: t.id, text: t.text })), text: p.text }))));
// llms.txt: what an agent should read, in order; llms-full.txt: all of it in one file.
const llms = [
	"# VXP · Verifiable eXchange Protocol",
	"",
	`> An open protocol for work that personal agents do for people inside companies. Two public components: VXP Proof (signed, verifiable evidence of each operation) and VXP Relationship (an authorized agreement within which the company can start a request toward the agent). Draft ${nav.version}, Apache 2.0.`,
	"",
	"The specification is the only normative text; the docs restate it and link to its rule identifiers.",
	"",
	...nav.sections.flatMap((s) => [`## ${s.title}`, "", ...s.pages.map((x) => {
		const p = todas.find((y) => y.slug === x.slug)!;
		return `- [${p.title}](${URL_BASE}/docs/${p.slug || "index"}.md): ${p.description}`;
	}), ""]),
	"## Normative",
	"",
	`- [Specification, draft ${nav.version}](${URL_BASE}/spec/): the rules, with stable identifiers (I, ID, E, P, R, O).`,
	`- [JSON Schemas ${nav.version}](${URL_BASE}/schemas/${nav.version}/index.json): every object of the protocol as JSON Schema 2020-12.`,
	"",
	"## Code",
	"",
	"- [Repository](https://github.com/vxp-protocol/vxp): specification source, reference implementation, agent tools, verifiers, vectors and conformance validator. AGENTS.md points coding agents at the right guide.",
	"",
].join("\n");
writeFileSync(join(SITE, "llms.txt"), llms);
writeFileSync(join(SITE, "llms-full.txt"), todas.map((p) => markdownPublicado(p)).join("\n\n---\n\n"));
// The JSON Schemas are published as they are in schemas/, at the URLs their $id names.
const ESQUEMAS = join(SITE, "schemas", nav.version);
rmSync(ESQUEMAS, { recursive: true, force: true });
cpSync(join(RAIZ, "schemas", nav.version), ESQUEMAS, { recursive: true });

if (errores.length) {
	console.error(errores.join("\n"));
	process.exit(1);
}
console.log(`docs: ${todas.length} pages → site/docs/, plus site/llms.txt, site/llms-full.txt and site/schemas/${nav.version}/`);
