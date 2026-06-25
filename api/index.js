const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN;
const MP_WEBHOOK_SECRET = process.env.MP_WEBHOOK_SECRET; // chave secreta do webhook (painel MP > Webhooks)
const SESSION_SECRET = process.env.SESSION_SECRET; // obrigatório em produção, usado p/ assinar tokens
const SITE_URL = process.env.SITE_URL || `https://${process.env.VERCEL_URL}` || "https://auto11labsv2.vercel.app";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "jjoaopedrojp27@gmail.com";
const LIMITE_GRATUITO = 10;
const LIMITE_CONTAS_POR_IP = 2;
const SESSION_TTL = 30 * 24 * 60 * 60 * 1000; // 30 dias

if (!SESSION_SECRET) {
  console.error("AVISO: SESSION_SECRET não configurado. Defina essa env var antes de ir para produção.");
}

// ── Rate limiting em memória (defesa best-effort; não sobrevive a cold start) ──
const rateMap = new Map(); // ip -> { count, reset }
const RATE_WINDOW = 60 * 1000; // 1 min
const RATE_MAX = 40; // max requisições por minuto por IP

function checkRate(ip) {
  const now = Date.now();
  const entry = rateMap.get(ip) || { count: 0, reset: now + RATE_WINDOW };
  if (now > entry.reset) { entry.count = 0; entry.reset = now + RATE_WINDOW; }
  entry.count++;
  rateMap.set(ip, entry);
  if (rateMap.size > 500) {
    for (const [k, v] of rateMap) { if (now > v.reset) rateMap.delete(k); }
  }
  return entry.count <= RATE_MAX;
}

function getIP(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.headers['x-real-ip'] || 'unknown';
}

// ── Supabase helper ───────────────────────────────────────
async function sb(method, path, body) {
  const url = `${SUPABASE_URL}/rest/v1/${path}`;
  const r = await fetch(url, {
    method,
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  try { return { ok: r.ok, status: r.status, data: JSON.parse(text) }; }
  catch { return { ok: r.ok, status: r.status, data: text }; }
}

// ── Log de pagamento ──────────────────────────────────────
async function logPagamento(tipo, dados, erro = null) {
  try {
    await sb("POST", "logs_pagamento", {
      tipo,
      dados: JSON.stringify(dados),
      erro: erro ? String(erro) : null,
      criado_em: new Date().toISOString(),
    });
  } catch (e) {
    console.error("Erro ao salvar log:", e);
  }
}

// ── Sessão (token assinado HMAC, sem estado no servidor) ──
function emitirToken(userId) {
  const payload = { uid: userId, exp: Date.now() + SESSION_TTL };
  const json = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const assinatura = crypto.createHmac("sha256", SESSION_SECRET || "dev-secret-inseguro")
    .update(json).digest("base64url");
  return `${json}.${assinatura}`;
}

function verificarToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [json, assinatura] = token.split(".");
  const esperada = crypto.createHmac("sha256", SESSION_SECRET || "dev-secret-inseguro")
    .update(json).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(assinatura), Buffer.from(esperada))) return null;
  try {
    const payload = JSON.parse(Buffer.from(json, "base64url").toString());
    if (!payload.uid || !payload.exp || Date.now() > payload.exp) return null;
    return payload.uid;
  } catch { return null; }
}

function pegarToken(req) {
  const auth = req.headers["authorization"] || "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : null;
}

// ── Handler principal ─────────────────────────────────────
module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const ip = getIP(req);
  const urlObj = new URL(req.url, "http://localhost");
  const path = urlObj.pathname.replace("/api/", "").replace("/api", "");

  if (path !== "webhook-mp" && !checkRate(ip)) {
    return res.status(429).json({ erro: "Muitas requisições. Aguarde um momento." });
  }

  const body = req.body || {};
  const query = Object.fromEntries(urlObj.searchParams);
  const ok = (data) => res.status(200).json(data);
  const err = (status, msg) => res.status(status).json({ erro: msg });

  // Retorna o id do usuário autenticado a partir do token, ou null
  async function usuarioAutenticado() {
    const uid = verificarToken(pegarToken(req));
    if (!uid) return null;
    const { data: users } = await sb("GET", `users?id=eq.${uid}&select=*`);
    return users && users[0] ? users[0] : null;
  }

  function publicUser(user) {
    return { id: user.id, email: user.email, plano: user.plano, audios_mes: user.audios_mes, is_admin: user.is_admin };
  }

  // ── POST /cadastrar ───────────────────────────────────
  if (path === "cadastrar" && req.method === "POST") {
    const { email, senha } = body;
    if (!email || !senha) return err(400, "Email e senha obrigatórios");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err(400, "Email inválido");
    if (senha.length < 6) return err(400, "Senha deve ter pelo menos 6 caracteres");

    const { data: existe } = await sb("GET", `users?email=eq.${encodeURIComponent(email)}&select=id`);
    if (existe && existe.length > 0) return err(400, "Email já cadastrado");

    const isAdmin = email.toLowerCase() === ADMIN_EMAIL.toLowerCase();
    if (!isAdmin) {
      const { data: contasIP } = await sb("GET", `users?ip_cadastro=eq.${encodeURIComponent(ip)}&plano=eq.gratuito&select=id`);
      if (contasIP && contasIP.length >= LIMITE_CONTAS_POR_IP) {
        return err(403, "Limite de contas gratuitas por rede atingido. Faça upgrade ou use outro email pago.");
      }
    }

    const senhaHash = await bcrypt.hash(senha, 10);
    const { data: novo } = await sb("POST", "users", {
      email,
      senha: senhaHash,
      is_admin: isAdmin,
      ip_cadastro: ip,
    });

    if (!novo || !novo[0]) return err(500, "Erro ao criar conta");
    const user = novo[0];
    return ok({ ok: true, token: emitirToken(user.id), user: publicUser(user) });
  }

  // ── POST /login ───────────────────────────────────────
  if (path === "login" && req.method === "POST") {
    const { email, senha } = body;
    if (!email || !senha) return err(400, "Email e senha obrigatórios");
    const { data: users } = await sb("GET", `users?email=eq.${encodeURIComponent(email)}&select=*`);
    if (!users || users.length === 0) return err(401, "Email ou senha incorretos");
    const user = users[0];
    const senhaOk = await bcrypt.compare(senha, user.senha || "");
    if (!senhaOk) return err(401, "Email ou senha incorretos");

    const mesAtual = new Date().toISOString().slice(0, 7);
    if (user.mes_referencia !== mesAtual) {
      await sb("PATCH", `users?id=eq.${user.id}`, { audios_mes: 0, mes_referencia: mesAtual });
      user.audios_mes = 0;
    }

    if (user.plano === "mensal" && user.plano_expira_em && new Date(user.plano_expira_em) < new Date()) {
      await sb("PATCH", `users?id=eq.${user.id}`, { plano: "gratuito" });
      user.plano = "gratuito";
    }

    return ok({ ok: true, token: emitirToken(user.id), user: publicUser(user) });
  }

  // ── GET /me (revalida sessão/recupera dados atuais) ───
  if (path === "me" && req.method === "GET") {
    const user = await usuarioAutenticado();
    if (!user) return err(401, "Sessão inválida");
    return ok({ ok: true, user: publicUser(user) });
  }

  // ── POST /registrar-audio ─────────────────────────────
  if (path === "registrar-audio" && req.method === "POST") {
    const user = await usuarioAutenticado();
    if (!user) return err(401, "Não autorizado");
    if (user.plano === "gratuito" && user.audios_mes >= LIMITE_GRATUITO) {
      return err(403, "Limite gratuito atingido");
    }
    const novoTotal = (user.audios_mes || 0) + 1;
    await sb("PATCH", `users?id=eq.${user.id}`, { audios_mes: novoTotal });
    return ok({ ok: true, audios_mes: novoTotal, restante: user.plano === "gratuito" ? LIMITE_GRATUITO - novoTotal : null });
  }

  // ── POST /criar-pagamento ─────────────────────────────
  if (path === "criar-pagamento" && req.method === "POST") {
    const user = await usuarioAutenticado();
    if (!user) return err(401, "Não autorizado");
    const { plano } = body;
    if (!plano) return err(400, "Parâmetros obrigatórios");

    const planos = {
      mensal: { titulo: "Auto11Labs — 2 Meses", preco: 44.90 },
      vitalicio: { titulo: "Auto11Labs — Vitalício", preco: 198.90 },
    };
    if (!planos[plano]) return err(400, "Plano inválido");
    const p = planos[plano];

    try {
      const mpRes = await fetch("https://api.mercadopago.com/checkout/preferences", {
        method: "POST",
        headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          items: [{ title: p.titulo, quantity: 1, unit_price: p.preco }],
          payer: { email: user.email },
          back_urls: {
            success: `${SITE_URL}/?pagamento=sucesso`,
            failure: `${SITE_URL}/?pagamento=falha`,
          },
          auto_return: "approved",
          notification_url: `${SITE_URL}/api/webhook-mp`,
          metadata: { user_id: user.id, plano },
        }),
      });

      const pref = await mpRes.json();
      if (!mpRes.ok) {
        await logPagamento("criar_preferencia_erro", { user_id: user.id, plano, resposta: pref });
        return err(500, "Erro ao criar pagamento");
      }

      await sb("POST", "pagamentos", { user_id: user.id, mp_preference_id: pref.id, plano, status: "pendente" });
      await logPagamento("preferencia_criada", { user_id: user.id, plano, preference_id: pref.id });
      return ok({ ok: true, url: pref.init_point });

    } catch (e) {
      await logPagamento("criar_preferencia_excecao", { user_id: user.id, plano }, e.message);
      return err(500, "Erro interno ao criar pagamento");
    }
  }

  // ── POST /webhook-mp (única fonte de verdade para ativar planos) ──
  if (path === "webhook-mp" && req.method === "POST") {
    const { type, data } = body;

    // Verifica assinatura do webhook quando configurada (recomendado pela MP)
    if (MP_WEBHOOK_SECRET) {
      const sigHeader = req.headers["x-signature"] || "";
      const requestId = req.headers["x-request-id"] || "";
      const parts = Object.fromEntries(sigHeader.split(",").map((p) => p.split("=").map((s) => s.trim())));
      const manifest = `id:${data?.id};request-id:${requestId};ts:${parts.ts};`;
      const esperada = crypto.createHmac("sha256", MP_WEBHOOK_SECRET).update(manifest).digest("hex");
      if (!parts.v1 || parts.v1 !== esperada) {
        await logPagamento("webhook_assinatura_invalida", { type, data_id: data?.id });
        return err(401, "Assinatura inválida");
      }
    }

    await logPagamento("webhook_recebido", { type, data_id: data?.id });
    if (type !== "payment") return ok({ ok: true });

    try {
      const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${data.id}`, {
        headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}` },
      });
      const pagamento = await mpRes.json();

      await logPagamento("webhook_payment_status", { payment_id: data.id, status: pagamento.status });

      if (pagamento.status !== "approved") return ok({ ok: true });

      const userId = pagamento.metadata?.user_id;
      const plano = pagamento.metadata?.plano;
      if (!userId || !plano) {
        await logPagamento("webhook_sem_metadata", { payment_id: data.id });
        return ok({ ok: true });
      }

      const expira = plano === "mensal" ? new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString() : null;
      await sb("PATCH", `users?id=eq.${userId}`, {
        plano: plano === "mensal" ? "mensal" : "vitalicio",
        plano_expira_em: expira,
      });
      await sb("PATCH", `pagamentos?mp_preference_id=eq.${pagamento.preference_id}`, {
        status: "aprovado",
        mp_payment_id: String(data.id),
      });
      await logPagamento("plano_ativado", { user_id: userId, plano, payment_id: data.id });

    } catch (e) {
      await logPagamento("webhook_excecao", { data_id: data?.id }, e.message);
    }

    return ok({ ok: true });
  }

  // ── GET /status-pagamento — apenas consulta, nunca escreve plano ──
  if (path === "status-pagamento" && req.method === "GET") {
    const user = await usuarioAutenticado();
    if (!user) return err(401, "Não autorizado");
    return ok({ ok: true, plano: user.plano, plano_expira_em: user.plano_expira_em || null });
  }

  // ── GET /admin/usuarios ───────────────────────────────
  if (path === "admin/usuarios" && req.method === "GET") {
    const admin = await usuarioAutenticado();
    if (!admin || !admin.is_admin) return err(403, "Acesso negado");
    const { data: users } = await sb("GET", "users?select=id,email,plano,audios_mes,plano_expira_em,criado_em,is_admin,ip_cadastro&order=criado_em.desc");
    return ok({ ok: true, users });
  }

  // ── GET /admin/logs ───────────────────────────────────
  if (path === "admin/logs" && req.method === "GET") {
    const admin = await usuarioAutenticado();
    if (!admin || !admin.is_admin) return err(403, "Acesso negado");
    const { data: logs } = await sb("GET", "logs_pagamento?select=*&order=criado_em.desc&limit=100");
    return ok({ ok: true, logs });
  }

  // ── POST /admin/alterar-plano ─────────────────────────
  if (path === "admin/alterar-plano" && req.method === "POST") {
    const admin = await usuarioAutenticado();
    if (!admin || !admin.is_admin) return err(403, "Acesso negado");
    const { user_id, plano } = body;
    if (!user_id || !plano) return err(400, "Parâmetros obrigatórios");
    const expira = plano === "mensal" ? new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString() : null;
    await sb("PATCH", `users?id=eq.${user_id}`, { plano, plano_expira_em: expira });
    await logPagamento("admin_alterou_plano", { admin_id: admin.id, user_id, plano });
    return ok({ ok: true });
  }

  // ── POST /admin/resetar-uso ───────────────────────────
  if (path === "admin/resetar-uso" && req.method === "POST") {
    const admin = await usuarioAutenticado();
    if (!admin || !admin.is_admin) return err(403, "Acesso negado");
    const { user_id } = body;
    if (!user_id) return err(400, "Parâmetros obrigatórios");
    await sb("PATCH", `users?id=eq.${user_id}`, { audios_mes: 0 });
    return ok({ ok: true });
  }

  return err(404, "Rota não encontrada");
};
