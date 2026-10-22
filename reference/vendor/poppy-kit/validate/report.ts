// `report`: drafts an implementation report from plan/feedback.md, plan/design.md, and
// .poppy/last-results.json, for the engineer to review and file. It never sends anything.

import { MILESTONES, type Milestone } from "./catalog.ts";
import type { CheckResult } from "./checks/types.ts";
import type { Design } from "./design.ts";
import { summarize } from "./output.ts";
import { redactText } from "./redact.ts";

export type LastResults = {
    generated_at?: string;
    target?: string;
    hosts?: string[];
    milestones?: Milestone[];
    results: CheckResult[];
};

const ISSUE_URL = "https://github.com/personal-agent-protocol/personal-agent-protocol/issues/new";
const MAX_URL = 8000;

// The registrable part of a host, roughly: example.com, or example.co.uk.
export function baseDomain(host: string): string {
    const labels = host.toLowerCase().replace(/:\d+$/, "").split(".");
    if (labels.length <= 2) return labels.join(".");
    const two = labels.slice(-2);
    return (two[0].length <= 3 && two[1].length <= 3 ? labels.slice(-3) : two).join(".");
}

// Replaces the Company's domains (and their subdomains) with example.com, and redacts tokens.
export function scrub(text: string, hosts: string[]): string {
    let out = redactText(text);
    const bases = [...new Set(hosts.filter(Boolean).map(baseDomain))]
        .filter((b) => b !== "example.com")
        .sort((a, b) => b.length - a.length);
    for (const base of bases) {
        const escaped = base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        out = out.replace(
            new RegExp(`\\b((?:[a-z0-9-]+\\.)*)${escaped}\\b`, "gi"),
            "$1example.com",
        );
    }
    return out;
}

// Splits feedback.md into kit feedback (sections whose heading mentions the kit or validator) and
// spec feedback (the rest).
export function splitFeedback(markdown: string): { spec: string; kit: string } {
    const spec: string[] = [];
    const kit: string[] = [];
    let target = spec;
    for (const line of markdown.split("\n")) {
        const heading = /^#{1,3}\s+(.*)$/.exec(line);
        if (heading) {
            if (/^#\s/.test(line)) continue;
            target = /\b(kit|validator|skill)\b/i.test(heading[1]) ? kit : spec;
        }
        // Feedback headings sit under the report's own ## sections.
        target.push(heading ? `### ${heading[1]}` : line);
    }
    return { spec: spec.join("\n").trim(), kit: kit.join("\n").trim() };
}

export function milestoneLines(results: CheckResult[]): string[] {
    const s = summarize(results);
    return MILESTONES.filter((m) => results.some((r) => r.milestone === m.id)).map((m) => {
        const n = s[m.id];
        const failing = results
            .filter((r) => r.milestone === m.id && r.status === "fail")
            .map((r) => r.id);
        const state =
            n.fail === 0 && n.pass > 0 ? "passing" : n.fail > 0 ? "failing" : "not checked";
        return `${m.number}. ${m.title}: ${state} (${n.pass} passed, ${n.fail} failed, ${n.warn} warnings, ${n.skip} skipped)${failing.length ? `. Failing: ${failing.join(", ")}` : ""}`;
    });
}

export function draftReport(input: { feedback?: string; design?: Design; last?: LastResults }): {
    markdown: string;
    url: string;
    fields: Record<string, string>;
} {
    const hosts = [
        ...(input.last?.hosts ?? []),
        ...(input.design?.domain ? [input.design.domain] : []),
    ];
    const results = input.last?.results ?? [];
    const design = input.design;
    const scope = [
        design?.interfaces?.length ? `Interfaces: ${design.interfaces.join(", ")}` : "",
        design?.sign_in?.length
            ? `Sign-in: ${design.sign_in.join(", ")}`
            : "Sign-in: none (signed-out Sessions only)",
        design?.extensions?.length ? `Extensions: ${design.extensions.join(", ")}` : "",
        design?.milestones?.length ? `Planned milestones: ${design.milestones.join(", ")}` : "",
    ]
        .filter(Boolean)
        .join("\n");
    const milestones = results.length
        ? milestoneLines(results).join("\n")
        : "No validator results yet (.poppy/last-results.json is missing).";
    const warnings = results.filter((r) => r.status === "warn").map((r) => r.id);
    const feedback = splitFeedback(input.feedback ?? "");
    const problems = [
        feedback.spec || "(Nothing in plan/feedback.md yet.)",
        warnings.length ? `\nValidator warnings: ${warnings.join(", ")}` : "",
    ]
        .join("")
        .trim();
    const fields: Record<string, string> = {
        role: "A company",
        scope: scrub(scope || "(Fill in.)", hosts),
        problems: scrub(problems, hosts),
        worked: "",
        milestones: scrub(milestones, hosts),
        kit: scrub(feedback.kit, hosts),
    };
    const markdown = [
        "# Implementation report (draft)",
        "",
        "> Review this draft before filing it. It leaves out hostnames (your domains are replaced with example.com), tokens, credentials, and anything about real users, but check that nothing sensitive is left in your feedback notes.",
        "",
        "## You implemented it as",
        "",
        fields.role,
        "",
        "## What you implemented",
        "",
        fields.scope,
        "",
        "## Milestones completed (validator results)",
        "",
        fields.milestones,
        "",
        "## What didn't work or was hard",
        "",
        fields.problems,
        "",
        "## What worked well",
        "",
        "(Fill in.)",
        "",
        "## Feedback on the kit",
        "",
        fields.kit || "(Nothing yet.)",
        "",
    ].join("\n");
    const params = new URLSearchParams({ template: "2-implementation-report.yml" });
    for (const [k, v] of Object.entries(fields)) if (v) params.set(k, v);
    let url = `${ISSUE_URL}?${params.toString()}`;
    if (url.length > MAX_URL) url = `${ISSUE_URL}?template=2-implementation-report.yml`;
    return { markdown, url, fields };
}
