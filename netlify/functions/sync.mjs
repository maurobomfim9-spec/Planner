// Guarda e devolve o bloco cifrado do Planner. O servidor nunca vê os dados em claro.
// A chave de armazenamento é o SHA-256 do token; sem o token (derivado da senha) não há acesso.
import { getStore } from "@netlify/blobs";
import { createHash } from "node:crypto";

const json = (status, body) => new Response(body ?? null, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });

export default async (req) => {
  const token = req.headers.get("x-planner-token") || "";
  if (!/^[0-9a-f]{64}$/.test(token)) return json(401, "sem token");
  const key = createHash("sha256").update(token).digest("hex");
  const store = getStore({ name: "planner", consistency: "strong" });

  if (req.method === "GET") {
    const data = await store.get(key);
    return data == null ? json(404) : json(200, data);
  }
  if (req.method === "PUT") {
    const body = await req.text();
    if (body.length > 5_000_000) return json(413, "grande demais");
    await store.set(key, body);
    return json(204);
  }
  return json(405);
};

export const config = { path: "/.netlify/functions/sync" };
