// Test aid of the REFERENCE implementation only, not part of VXP: makes the reference company start a request
// inside a relationship, through the reference's internal test route (a company's own console in a real
// deployment). Env: VXP_RELATIONSHIP_ID, VXP_ACTION, VXP_KIND, VXP_EXPECT_REFUSAL (from the validator);
// REF_ORIGIN, REF_INTERNAL_KEY, REF_TENANT, REF_PROPOSAL_PARAMS and REF_QUESTION_PARAMS (JSON).
const params = JSON.parse(process.env.VXP_KIND === "question" ? process.env.REF_QUESTION_PARAMS : process.env.REF_PROPOSAL_PARAMS);
const r = await fetch(`${process.env.REF_ORIGIN}/interno/relaciones/iniciar`, {
	method: "POST",
	headers: { "x-sovras-prueba": process.env.REF_INTERNAL_KEY, "content-type": "application/json" },
	body: JSON.stringify({ tenant: process.env.REF_TENANT, relationship_id: process.env.VXP_RELATIONSHIP_ID, action: process.env.VXP_ACTION, params }),
});
const body = await r.json();
console.log(`company request (${process.env.VXP_KIND}): ${body.error ?? body.delivery ?? r.status}`);
process.exit(body.error && !process.env.VXP_EXPECT_REFUSAL ? 1 : 0);
