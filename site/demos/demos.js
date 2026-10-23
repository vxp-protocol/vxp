// List of standalone interactive demos. Reads demos.json and draws one card per demo.
// Each demo lives in its own folder, demos/<name>/, and imports nothing from the site's normative code.
// With "embed": "page" its page is linked; with "embed": "iframe" it is embedded here, only on request.
const lista = document.querySelector("[data-demos]");
const vacio = document.querySelector("[data-demos-empty]");
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const nombreValido = (n) => /^[a-z0-9][a-z0-9-]{0,62}$/.test(n);

fetch("demos.json", { cache: "no-cache" })
	.then((r) => (r.ok ? r.json() : { demos: [] }))
	.then(({ demos = [] }) => {
		const validas = demos.filter((d) => nombreValido(d.slug) && d.title);
		if (!validas.length) return;
		vacio.hidden = true;
		lista.hidden = false;
		lista.innerHTML = validas.map((d) => `
			<li class="dm" id="demo-${d.slug}">
				<p class="dm__top"><b>${esc(d.kind ?? "Demo")}</b><span>${esc(d.lang ?? "")}</span></p>
				<h3>${esc(d.title)}</h3>
				<p>${esc(d.description)}</p>
				${d.embed === "iframe"
					? `<button type="button" class="btn btn--ghost" data-load="${d.slug}" aria-expanded="false" aria-controls="frame-${d.slug}">Load the demo here</button>
					   <div class="dm__frame" id="frame-${d.slug}" hidden data-title="${esc(d.title)}" data-height="${Number(d.height) || 640}"></div>
					   <a href="${d.slug}/">Open it on its own page</a>`
					: `<a class="btn btn--ghost" href="${d.slug}/">Open the demo</a>`}
			</li>`).join("");
		lista.querySelectorAll("[data-load]").forEach((b) => b.addEventListener("click", () => {
			const caja = document.getElementById(`frame-${b.dataset.load}`);
			if (!caja.firstChild) {
				const f = document.createElement("iframe");
				f.src = `${b.dataset.load}/`;
				f.title = caja.dataset.title;
				f.loading = "lazy";
				f.height = caja.dataset.height;
				f.setAttribute("sandbox", "allow-scripts allow-forms allow-same-origin");
				caja.append(f);
			}
			const abrir = caja.hidden;
			caja.hidden = !abrir;
			b.setAttribute("aria-expanded", String(abrir));
			b.textContent = abrir ? "Hide the demo" : "Load the demo here";
		}));
	})
	.catch(() => {});
