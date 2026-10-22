"""Outcome-proof mutations: remove each protection of the issuer or the gateway, run the tests and
confirm that at least one fails; then restore the file (.bak copy) and move on.

Usage (from the proof-of-concept root): python scripts/mutar-prueba.py
"""
import shutil
import subprocess

PRUEBAS = "node --test test/prueba-resultado.test.ts test/poppy-flujo.test.ts test/ataques-ronda-3.test.ts test/ronda-4.test.ts"

M = [
    ("P1 sin lectura de vuelta (no se emite read_back)", "src/nucleo.ts",
     "\t\t\tconst lectura = this.eslabon(\n\t\t\t\ttenantId,\n\t\t\t\top,\n\t\t\t\t\"operador\",\n\t\t\t\t\"read_back\",",
     "\t\t\tconst lectura = null;\n\t\t\tif (false) this.eslabon(\n\t\t\t\ttenantId,\n\t\t\t\top,\n\t\t\t\t\"operador\",\n\t\t\t\t\"read_back\","),
    ("P2 lectura que no calza igual da succeeded", "src/nucleo.ts",
     # Anchor in the rescheduling path (the purchase has another read-back with the same text on one line).
     "				{ method: \"system_read_back\", source: \"company_system\", matches_terms: true, observed: observado },",
     "				{ method: \"system_read_back\", source: \"company_system\", matches_terms: false, observed: observado },"),
    ("P3 sin encadenar (prev siempre null)", "src/prueba.ts",
     "prev: previa ? previa.digest : null,", "prev: null,"),
    ("P4 huella de términos sin summary", "src/prueba.ts",
     "\t\tsummary: t.summary,\n", ""),
    ("P5 revisión nueva sin firmar sus términos", "src/nucleo.ts",
     "\t\t\t\tthis.firmarTerminos(actor.tenantId, existente);\n", ""),
    ("P6 el operador firma todo con su llave (sin separación de roles)", "src/prueba.ts",
     "firmarJws(rol === \"empresa\" ? e.llave : this.operador,", "firmarJws(this.operador,"),
    ("P7 dirección en claro en la lectura de vuelta", "src/nucleo.ts",
     "observed: observado },\n\t\t\t\t{ observed: { direccion: leido.direccion } },",
     "observed: { ...observado, direccion: leido.direccion } },\n\t\t\t\t{},"),
    ("P8 aud fijo (no el client_id del agente)", "src/prueba.ts",
     "\t\t\taud: c.aud,", "\t\t\taud: \"https://cualquier-agente\","),
    ("P9 kid que no es el thumbprint RFC 7638", "src/prueba.ts",
     "const kid = b64u(sha(jcs(miembros)));", "const kid = b64u(randomBytes(32));"),
    ("P10 payload sin canonicalizar (JSON.stringify en orden de inserción)", "src/prueba.ts",
     "const p = b64u(jcs(payload));", "const p = b64u(JSON.stringify(payload));"),
    ("P11 no se registra la hoja en el registro", "src/prueba.ts",
     "\t\tthis.hojas.push(entrada);", "\t\tvoid entrada;"),
    ("P12 paquete sin regla de dueño", "src/poppy.ts",
     "const op = this.nucleo.operacionDe(a, resto[1], sesion.id);\n\t\t// Owner rules",
     "const op0 = this.nucleo.operacionDe(a, resto[1], sesion.id);\n\t\tconst op = typeof op0 === \"string\" ? ([...this.nucleo.base(e.tenantId).operaciones.values()].find((o) => o.operation_id === resto[1]) ?? op0) : op0;\n\t\t// Owner rules"),
    ("P13 miembro de la extensión también a quien no la lista", "src/poppy.ts",
     "if (conPrueba && latest)", "if (latest)"),
    ("P14 revisión nueva no reevalúa la regla de la empresa", "src/nucleo.ts",
     "\t\t\t\tif (!revisionNueva) existente.interno.revisionEmpresa = null;\n\t\t\t\telse if (!existente.interno.revisionEmpresa) existente.interno.revisionEmpresa = revisionNueva;\n", ""),
    ("P15 el emisor deja firmar cualquier kind a cualquier rol", "src/prueba.ts",
     "if (!KIND_DE_ROL[rol].includes(kind)) throw", "if (false) throw"),
    # Validation round 1.
    ("P16 la metadata del issuer no publica el ancla (B1)", "src/poppy.ts",
     "\t\t\tvxp_proof: bloqueConfianza({", "\t\t\tvxp_proof_no: bloqueConfianza({"),
    ("P17 la copia de poppy.json nombra otro jwks_uri que la metadata (B1)", "src/prueba.ts",
     "\t\t...bloqueConfianza(p),\n", "\t\t...bloqueConfianza(p),\n\t\tjwks_uri: `${p.authOrigin}/otras-llaves.json`,\n"),
    ("P18 la huella de la declaracion cubre la firma (m1)", "src/prueba.ts",
     "\t\t\tdigest: huellaDeclaracion(jwt),", "\t\t\tdigest: huellaBytes(Buffer.from(jwt, \"ascii\")),"),
    # Round 2 (interoperability).
    ("P19 se ignora la version que lista el agente (m5)", "src/poppy.ts",
     "doc?.extensions?.[EXT_PRUEBA]?.version === VERSION_PRUEBA;", "doc?.extensions?.[EXT_PRUEBA] !== undefined;"),
    ("P20 la metadata no declara los vinculos de marca y PACT (M1)", "src/prueba.ts",
     "\t\t...(p.vinculos ? { domains: p.vinculos.domains, pact: p.vinculos.pact } : {}),\n", ""),
    ("P21 el AS de PACT no publica la copia del bloque (M1)", "src/pact.ts",
     "\t\t\t...(this.nucleo.pruebas\n", "\t\t\t...(false && this.nucleo.pruebas\n"),
    # Round 3 (red team): removing each fix must make a test fail.
    ("P22 lo observado vuelve a llamarse `despacho` (M1)", "src/datos.ts",
     "lecturaDeVuelta: { pedido: \"id\", despacho_nuevo: \"despacho\" },", "lecturaDeVuelta: { pedido: \"id\", despacho: \"despacho\" },"),
    ("P23 la revision no declara que terminos observar (M1)", "src/nucleo.ts",
     "\t\t\tread_back_terms: [...Object.keys(this.capacidad(tenantId, op).lecturaDeVuelta ?? {}), ...op.interno.nativo.compromiso.requires],\n", ""),
    ("P24 reutilizar sin el dueno completo (M2)", "src/nucleo.ts",
     "existente.interno.intent.inputs.pedidoId === pedidoId && this.esDueno(existente, actor, sesion)",
     "existente.interno.intent.inputs.pedidoId === pedidoId && existente.interno.dueno.clienteId === actor.clienteId"),
    ("P25 revision nueva sin registrar la peticion (M2)", "src/nucleo.ts",
     "\t\t\t\tif (!existente.interno.counterPendiente)\n", "\t\t\t\tif (false)\n"),
    ("P26 sin precondicion antes de ejecutar (M3)", "src/nucleo.ts",
     "if (!actual || actual.despacho !== op.terms.despacho_actual) {", "if (!actual) {"),
    ("P27 sin bloqueo de una operacion en curso por pedido (M3)", "src/nucleo.ts",
     "\t\t\treturn { ok: false, falta: \"en_curso\" };", "\t\t\tvoid 0;"),
    ("P28 nivel con el nombre retirado (m1)", "src/nucleo.ts",
     "\"operator_reported_channel_approval\" : \"operator_reported_agent_approval\");", "\"operator_reported_channel_approval\" : \"agent_asserted_approval\");"),
    ("P29 terminos sin sal (m2)", "src/nucleo.ts",
     "\t\t\tvxp_salt: randomBytes(16).toString(\"base64url\"),\n", ""),
    ("P30 la revision no declara si la empresa exige la suya (m3)", "src/nucleo.ts",
     "company_review_required: op.interno.revisionEmpresa !== null,", "company_review_required: false,"),
    ("P31 WhatsApp acepta sin mirar el estado ni la confirmacion (m4, sus dos defensas)", "src/pact.ts",
     ["\t\tif (op.state !== \"proposed\") {\n\t\t\tthis.nucleo.evento(tenantId, op.interno.caseId, \"approval.ignored_out_of_band\"",
      "return r.status === 200 && op.confirmation?.revision === ap.revision;"],
     ["\t\tif (false) {\n\t\t\tthis.nucleo.evento(tenantId, op.interno.caseId, \"approval.ignored_out_of_band\"",
      "return r.status === 200;"]),
    # Round 4: removing each fix must make a test fail.
    ("P32 la autoridad agente_personal no pide revision con `toda_escritura` (M1)", "src/nucleo.ts",
     "\t\t\tif (empresa.reglaRevisionAgentes === \"toda_escritura\")\n", "\t\t\tif (false)\n"),
    ("P33 la decision del cliente no lleva su principal (M1)", "src/nucleo.ts",
     "\t\t\tprincipal: { tipo: \"cliente\", cliente: actor.clienteId, ref: `agent:${actor.clientId}#${actor.sub}` },\n", ""),
    ("P34 la verdad de la operacion vuelve a salir de `outcome.verified` (M3)", "src/nucleo.ts",
     "\"tool.verified\", { method: \"read_back\", operation_id: op.operation_id, revision", "\"outcome.verified\", { method: \"read_back\", operation_id: op.operation_id, revision"),
    ("P35 sin ventana de 24 h: siempre texto libre (M5)", "src/nucleo.ts",
     "const via = abierta ? \"ventana_de_servicio\" : empresa.plantillasWhatsApp[m.proposito] ? \"plantilla\" : null;",
     "const via = \"ventana_de_servicio\" as const;"),
    ("P36 la aprobacion sale sin consentimiento de servicio (M5)", "src/nucleo.ts",
     "if (m.proposito === \"aprobacion\" && !cliente.whatsapp.consentimientoServicio)", "if (false)"),
    ("P37 la aprobacion no entregada igual queda esperando un codigo (M5)", "src/pact.ts",
     "\t\tif (!entrega.entregado) {", "\t\tif (false && !entrega.entregado) {"),
    ("P38 la lectura filtra por el id del operador y no por el vinculo con el ERP (M6)", "src/nucleo.ts",
     "const pedidos = erp ? this.empresa(actor.tenantId).sistema.pedidos.filter((p) => p.clienteId === erp) : [];",
     "const pedidos = this.empresa(actor.tenantId).sistema.pedidos.filter((p) => p.clienteId === erp || p.clienteId === actor.clienteId);"),
    ("P39 sin vinculo con el ERP se escribe igual (M6)", "src/nucleo.ts",
     "hechos.recurso = !erp ? \"sin_vinculo\" :", "hechos.recurso = !erp ? \"propio\" :"),
]

detectadas = 0
for nombre, f, a, b in M:
    s = open(f, encoding="utf-8").read()
    # One mutation can remove several defenses from the same file: `a` and `b` as parallel lists.
    for x in (a if isinstance(a, list) else [a]):
        # Demanding sandbox: in the 02:55 original two anchors (P2, P5) already appear twice (the purchase
        # repeats the rescheduling text). The FIRST one, the rescheduling one, is mutated, with a notice.
        assert s.count(x) >= 1, "ancla no encontrada: " + nombre
        if s.count(x) > 1: print("  (ancla repetida %d veces; se muta la primera) %s" % (s.count(x), nombre))
    mutado = s
    for x, y in zip(a if isinstance(a, list) else [a], b if isinstance(b, list) else [b]):
        mutado = mutado.replace(x, y, 1)
    shutil.copy(f, f + ".bak")
    try:
        open(f, "w", encoding="utf-8").write(mutado)
        r = subprocess.run(PRUEBAS, shell=True, capture_output=True, text=True, encoding="utf-8")
    finally:
        shutil.move(f + ".bak", f)
    fallan = [l for l in r.stdout.splitlines() if l.startswith("not ok")]
    detectadas += 1 if fallan else 0
    print(("DETECTADA    " if fallan else "NO DETECTADA ") + nombre + " -> " + "; ".join(x[7:80] for x in fallan[:3]))
print("\n%d/%d detectadas" % (detectadas, len(M)))
