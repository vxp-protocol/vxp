// Mutation switches for the native-profile and VXP tests.
// Each name disables ONE protection. `scripts/mutar-nativo.mjs` runs the tests with each one and
// requires at least one to fail. Without the variable, no protection is disabled.

const activas = new Set((process.env.SOVRAS_MUTAR ?? "").split(",").map((x) => x.trim()).filter(Boolean));

export const mutado = (nombre: string): boolean => activas.has(nombre);
