// Comportamiento común: menú en móvil, titular palabra por palabra y botones de copiar código.
(() => {
	const menu = document.querySelector(".nav__menu");
	const lista = document.getElementById("menu");
	if (menu && lista) {
		menu.addEventListener("click", () => {
			const abierto = lista.classList.toggle("open");
			menu.setAttribute("aria-expanded", String(abierto));
		});
	}

	for (const h of document.querySelectorAll(".reveal-words")) {
		const palabras = h.textContent.trim().split(/\s+/);
		h.setAttribute("aria-label", h.textContent.trim());
		h.textContent = "";
		// Con data-lines, cada frase va en su propia línea.
		let linea = h.hasAttribute("data-lines") ? document.createElement("span") : h;
		if (linea !== h) { linea.className = "line"; h.append(linea); }
		palabras.forEach((p, i) => {
			const s = document.createElement("span");
			s.className = "word";
			s.setAttribute("aria-hidden", "true");
			s.style.transitionDelay = `${0.25 + i * 0.045}s`;
			s.textContent = p;
			linea.append(s, " ");
			if (linea !== h && /[.!?]$/.test(p) && i < palabras.length - 1) {
				linea = document.createElement("span");
				linea.className = "line";
				h.append(linea);
			}
		});
		requestAnimationFrame(() => requestAnimationFrame(() => h.classList.add("go")));
	}

	for (const pre of document.querySelectorAll("pre[data-copy]")) {
		const b = document.createElement("button");
		b.type = "button";
		b.className = "copy";
		b.textContent = "Copy";
		b.addEventListener("click", async () => {
			try {
				await navigator.clipboard.writeText(pre.innerText);
				b.textContent = "Copied";
			} catch {
				b.textContent = "Select and copy";
			}
			setTimeout(() => (b.textContent = "Copy"), 1600);
		});
		pre.parentElement.insertBefore(b, pre);
	}
})();
