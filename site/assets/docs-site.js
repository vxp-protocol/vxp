// Documentation pages: client-side search over search-index.json, and the sidebar folded on small screens.
(() => {
	const raiz = document.body.dataset.root || "../";
	const q = document.getElementById("dsearch-q");
	const lista = document.getElementById("dsearch-r");
	const plegable = document.querySelector(".dnav__wrap");
	if (plegable && window.matchMedia("(max-width: 900px)").matches) plegable.removeAttribute("open");
	if (!q || !lista) return;
	let indice = null;
	const cargar = () => indice ?? fetch(`${raiz}docs/search-index.json`).then((r) => r.json()).then((x) => (indice = x));
	const url = (p, id) => `${raiz}docs/${p.slug}${p.slug ? "/" : ""}${id ? `#${id}` : ""}`;
	const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
	function buscar(texto) {
		const t = texto.toLowerCase().trim().split(/\s+/).filter(Boolean);
		if (!t.length) return [];
		const out = [];
		for (const p of indice) {
			const enTitulo = t.every((w) => p.title.toLowerCase().includes(w));
			for (const h of p.headings) if (t.every((w) => h.text.toLowerCase().includes(w))) out.push({ score: 3, href: url(p, h.id), title: h.text, sub: p.title });
			const cuerpo = `${p.title} ${p.description} ${p.text}`.toLowerCase();
			if (t.every((w) => cuerpo.includes(w))) {
				const i = cuerpo.indexOf(t[0]);
				const frag = `${p.title} ${p.description} ${p.text}`.slice(Math.max(0, i - 40), i + 90).replace(/\s+/g, " ");
				out.push({ score: enTitulo ? 4 : 1, href: url(p), title: p.title, sub: `…${frag}…` });
			}
		}
		return out.sort((a, b) => b.score - a.score).slice(0, 12);
	}
	let sel = -1;
	q.addEventListener("input", async () => {
		await cargar();
		const r = buscar(q.value);
		sel = -1;
		lista.hidden = !q.value.trim();
		lista.innerHTML = r.length ? r.map((x) => `<li><a href="${x.href}">${esc(x.title)}<small>${esc(x.sub)}</small></a></li>`).join("") : `<li class="none">No results</li>`;
	});
	q.addEventListener("keydown", (e) => {
		const as = [...lista.querySelectorAll("a")];
		if (e.key === "ArrowDown" || e.key === "ArrowUp") {
			e.preventDefault();
			sel = Math.max(0, Math.min(as.length - 1, sel + (e.key === "ArrowDown" ? 1 : -1)));
			as.forEach((a, i) => a.setAttribute("aria-selected", String(i === sel)));
		} else if (e.key === "Enter" && as[Math.max(sel, 0)]) {
			e.preventDefault();
			location.href = as[Math.max(sel, 0)].href;
		} else if (e.key === "Escape") {
			lista.hidden = true;
		}
	});
	document.addEventListener("click", (e) => {
		if (!e.target.closest(".dsearch")) lista.hidden = true;
	});
	document.addEventListener("keydown", (e) => {
		if (e.key === "/" && document.activeElement !== q && !/input|textarea/i.test(document.activeElement.tagName)) {
			e.preventDefault();
			q.focus();
		}
	});
})();
