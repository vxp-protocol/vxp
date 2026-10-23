// The person, played by a test: opens the company's verification page, types their phone number,
// types the code their phone received, reads the consent screen and presses «Permitir». Only what a
// person with a browser does: plain HTTP to the company's own page, following its forms.

const field = (html: string, name: string) => html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1] ?? null;
const action = (html: string) => html.match(/<form method="post" action="([^"]+)"/)?.[1] ?? null;

export type ConsentScreen = { text: string; scopes: { value: string; label: string }[] };

async function post(origin: string, path: string, form: [string, string][]) {
	const body = new URLSearchParams();
	for (const [k, v] of form) body.append(k, v);
	const r = await fetch(new URL(path, origin), { method: "POST", body, redirect: "manual" });
	return { status: r.status, html: await r.text(), location: r.headers.get("location") };
}

/**
 * Links the account on the company's page and approves. `readCode` is the person reading their phone.
 * `untick` lists scope values the person leaves unticked (e.g. the relationship checkbox).
 */
export async function approveOnCompanyPage(verificationUrl: string, phone: string, readCode: () => Promise<string>, o: { untick?: string[]; deny?: boolean } = {}): Promise<{ consent: ConsentScreen; result: string | null }> {
	const origin = new URL(verificationUrl).origin;
	const first = await (await fetch(verificationUrl)).text();
	const userCode = field(first, "user_code");
	const a1 = action(first);
	if (!userCode || !a1) throw new Error(`unexpected verification page:\n${first}`);
	const sent = await post(origin, a1, [["user_code", userCode], ["telefono", phone]]);
	const a2 = action(sent.html);
	if (!a2) throw new Error(`unexpected page after the phone number:\n${sent.html}`);
	const code = await readCode();
	const screen = await post(origin, a2, [["user_code", userCode], ["codigo", code]]);
	const a3 = action(screen.html);
	if (!a3) throw new Error(`unexpected consent page:\n${screen.html}`);
	const scopes = [...screen.html.matchAll(/<input type="checkbox" name="scope" value="([^"]+)" checked> ([^<]+)<\/label>/g)].map((m) => ({ value: m[1], label: m[2] }));
	const text = screen.html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
	const keep = scopes.filter((s) => !(o.untick ?? []).includes(s.value)).map((s) => ["scope", s.value] as [string, string]);
	const done = await post(origin, a3, [["user_code", userCode], ...keep, ["decision", o.deny ? "deny" : "allow"]]);
	return { consent: { text, scopes }, result: done.location };
}

/**
 * The person approves (or denies) exact terms on their own agent's approval page, typing the code they
 * read in their own terminal (`vxp-agent approvals`).
 */
export async function decideOnAgentPage(approvalUrl: string, code: string, approve: boolean): Promise<{ status: number; text: string }> {
	const page = await (await fetch(approvalUrl)).text();
	const r = await fetch(approvalUrl, { method: "POST", body: new URLSearchParams({ code, decision: approve ? "approve" : "deny" }) });
	const text = (s: string) => s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
	return { status: r.status, text: `${text(page)} → ${text(await r.text())}` };
}
