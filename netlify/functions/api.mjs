import { getStore } from "@netlify/blobs";
import { randomUUID, createHash, randomBytes } from "node:crypto";

// ── Helpers ──────────────────────────────────────────────
const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

const sha = (s) => createHash("sha256").update(s).digest("hex");

// Single global store for the shop. Strong consistency so the admin sees
// his changes immediately and customers get them within seconds.
function shop() {
  return getStore({ name: "perfect-shop", consistency: "strong" });
}

const DEFAULT_PASSWORD = "Admin123";

// Get (and lazily initialise) the admin auth record
async function getAuth(store) {
  let auth = await store.get("auth", { type: "json" });
  if (!auth) {
    auth = { passHash: sha(DEFAULT_PASSWORD), tokens: {} };
    await store.setJSON("auth", auth);
  }
  return auth;
}

async function requireAuth(store, req) {
  const token = (req.headers.get("authorization") || "").replace("Bearer ", "");
  if (!token) return false;
  const auth = await getAuth(store);
  const exp = auth.tokens?.[token];
  if (!exp) return false;
  if (Date.now() > exp) {
    // expired – clean it up
    delete auth.tokens[token];
    await store.setJSON("auth", auth);
    return false;
  }
  return true;
}

// ── Function ─────────────────────────────────────────────
export default async (req) => {
  const url = new URL(req.url);
  const action = url.searchParams.get("action") || "";
  const store = shop();

  try {
    // ---- PUBLIC: list products (used by main site + admin) ----
    if (req.method === "GET" && action === "products") {
      const products = (await store.get("products", { type: "json" })) || [];
      return json({ products });
    }

    // ---- PUBLIC: fetch a single product image ----
    if (req.method === "GET" && action === "image") {
      const id = url.searchParams.get("id");
      if (!id) return json({ error: "missing id" }, 400);
      const imgStore = getStore({ name: "perfect-images", consistency: "strong" });
      const blob = await imgStore.get(id, { type: "arrayBuffer" });
      if (!blob) return new Response("Not found", { status: 404 });
      const meta = await imgStore.getMetadata(id);
      return new Response(blob, {
        status: 200,
        headers: {
          "content-type": meta?.metadata?.type || "image/jpeg",
          "cache-control": "public, max-age=300",
        },
      });
    }

    // ---- LOGIN ----
    if (req.method === "POST" && action === "login") {
      const { password } = await req.json();
      const auth = await getAuth(store);
      if (sha(password || "") !== auth.passHash) {
        return json({ error: "Wrong password" }, 401);
      }
      const token = randomBytes(24).toString("hex");
      // token valid 12 hours
      auth.tokens = auth.tokens || {};
      auth.tokens[token] = Date.now() + 12 * 60 * 60 * 1000;
      // prune expired tokens
      for (const [t, exp] of Object.entries(auth.tokens)) {
        if (Date.now() > exp) delete auth.tokens[t];
      }
      await store.setJSON("auth", auth);
      return json({ token });
    }

    // ---- everything below requires auth ----
    const authed = await requireAuth(store, req);
    if (!authed) return json({ error: "Unauthorized" }, 401);

    // ---- CHANGE PASSWORD ----
    if (req.method === "POST" && action === "change-password") {
      const { current, next } = await req.json();
      const auth = await getAuth(store);
      if (sha(current || "") !== auth.passHash) {
        return json({ error: "Current password is incorrect" }, 401);
      }
      if (!next || next.length < 4) {
        return json({ error: "New password must be at least 4 characters" }, 400);
      }
      auth.passHash = sha(next);
      auth.tokens = {}; // force re-login everywhere
      await store.setJSON("auth", auth);
      return json({ ok: true });
    }

    // ---- ADD / UPDATE PRODUCT ----
    if (req.method === "POST" && action === "save-product") {
      const body = await req.json();
      const products = (await store.get("products", { type: "json" })) || [];
      const imgStore = getStore({ name: "perfect-images", consistency: "strong" });

      // Handle images: array of { data: dataURL } or existing { id }
      const imageIds = [];
      for (const img of body.images || []) {
        if (img.id) {
          imageIds.push(img.id);
        } else if (img.data) {
          const m = img.data.match(/^data:(image\/[a-zA-Z+]+);base64,(.+)$/);
          if (!m) continue;
          const type = m[1];
          const buf = Buffer.from(m[2], "base64");
          const imgId = randomUUID();
          await imgStore.set(imgId, buf, { metadata: { type } });
          imageIds.push(imgId);
        }
      }

      const product = {
        id: body.id || randomUUID(),
        name: body.name || "Untitled",
        price: body.price || "",
        sizes: body.sizes || [],
        category: body.category || "Shirts",
        desc: body.desc || "",
        images: imageIds,
        updated: Date.now(),
      };

      const idx = products.findIndex((p) => p.id === product.id);
      if (idx >= 0) products[idx] = product;
      else products.unshift(product);

      await store.setJSON("products", products);
      return json({ ok: true, product });
    }

    // ---- DELETE PRODUCT ----
    if (req.method === "POST" && action === "delete-product") {
      const { id } = await req.json();
      let products = (await store.get("products", { type: "json" })) || [];
      const target = products.find((p) => p.id === id);
      products = products.filter((p) => p.id !== id);
      await store.setJSON("products", products);
      // best-effort image cleanup
      if (target?.images?.length) {
        const imgStore = getStore({ name: "perfect-images", consistency: "strong" });
        for (const imgId of target.images) {
          try { await imgStore.delete(imgId); } catch {}
        }
      }
      return json({ ok: true });
    }

    // ---- LOGOUT ----
    if (req.method === "POST" && action === "logout") {
      const token = (req.headers.get("authorization") || "").replace("Bearer ", "");
      const auth = await getAuth(store);
      if (auth.tokens?.[token]) {
        delete auth.tokens[token];
        await store.setJSON("auth", auth);
      }
      return json({ ok: true });
    }

    return json({ error: "Unknown action" }, 400);
  } catch (err) {
    return json({ error: String(err?.message || err) }, 500);
  }
};

export const config = {
  path: "/api",
};
