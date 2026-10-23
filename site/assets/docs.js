// Documentation: sticky table of contents on desktop, collapsible on mobile, with the current section marked.
(() => {
	const toc = document.querySelector(".toc details");
	if (!toc) return;
	const escritorio = matchMedia("(min-width: 1001px)");
	const ajustar = () => { toc.open = escritorio.matches; };
	ajustar();
	escritorio.addEventListener("change", () => { toc.open = escritorio.matches; });

	// On mobile, choosing a section closes the table of contents.
	toc.addEventListener("click", (e) => {
		if (e.target.closest("a") && !escritorio.matches) toc.open = false;
	});

	const enlaces = [...toc.querySelectorAll(":scope > ol > li > a")];
	const secciones = enlaces.map((a) => document.getElementById(a.getAttribute("href").slice(1))).filter(Boolean);
	const marcar = () => {
		const y = window.scrollY + 160;
		let actual = secciones[0];
		for (const s of secciones) if (s.offsetTop <= y) actual = s;
		for (const a of enlaces) {
			if (a.getAttribute("href") === `#${actual.id}`) a.setAttribute("aria-current", "location");
			else a.removeAttribute("aria-current");
		}
	};
	let pendiente = false;
	window.addEventListener("scroll", () => {
		if (pendiente) return;
		pendiente = true;
		requestAnimationFrame(() => { marcar(); pendiente = false; });
	}, { passive: true });
	marcar();
})();
