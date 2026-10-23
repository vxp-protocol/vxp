// Runs a command without blocking the event loop. A spawnSync that lasts longer than a server's
// keep-alive timeout lets the server close pooled sockets, and the next fetch then fails (ECONNRESET).

import { spawn } from "node:child_process";

export function run(cmd: string, args: string[], timeoutMs = 60_000): Promise<{ status: number | null; stdout: string; stderr: string }> {
	return new Promise((ok, fail) => {
		const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		p.stdout.setEncoding("utf8").on("data", (d) => (stdout += d));
		p.stderr.setEncoding("utf8").on("data", (d) => (stderr += d));
		const t = setTimeout(() => p.kill(), timeoutMs);
		p.once("error", (e) => {
			clearTimeout(t);
			fail(e);
		});
		p.once("close", (status) => {
			clearTimeout(t);
			ok({ status, stdout, stderr });
		});
	});
}
