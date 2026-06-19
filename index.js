const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN;
const SITE_URL = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "https://seusite.vercel.app";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "jjoaopedrojp27@gmail.com";
const LIMITE_GRATUITO = 10;

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
  try { return { ok: r.ok, data: JSON.parse(text) }; }
  catch { return { ok: r.ok, data: text }; }
}

function hashSenha(senha) {
  let hash = 0;
  const str = senha + "a11labs_salt_2025";
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(36) + str.length.toString(36) + "x" + (hash >>> 16).toString(36);
}

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const urlObj = new URL(req.url, "http://localhost");
  const path = urlObj.pathname.replace("/api/", "").replace("/api", "");
  const body = req.body || {};
  const query = Object.fromEntries(urlObj.searchParams);

  const ok = (data) => res.status(200).json(data);
  const err = (status, msg) => res.status(status).json({ erro: msg });

  // POST /cadastrar
  if (path === "cadastrar" && req.method === "POST") {
    const { email, senha } = body;
    if (!email || !senha) return err(400, "Email e senha obrigatórios");
    if (senha.length < 6) return err(400, "Senha deve ter pelo menos 6 caracteres");
    const { data: existe } = await sb("GET", `users?email=eq.${encodeURIComponent(email)}&select=id`);
    if (existe && existe.length > 0) return err(400, "Email já cadastrado");
    const isAdmin = email.toLowerCase() === ADMIN_EMAIL.toLowerCase();
    const { data: novo } = await sb("POST", "users", { email, senha: hashSenha(senha), is_admin: isAdmin });
    const user = novo[0];
    return ok({ ok: true, user: { id: user.id, email: user.email, plano: user.plano, audios_mes: user.audios_mes, is_admin: user.is_admin } });
  }

  // POST /login
  if (path === "login" && req.method === "POST") {
    const { email, senha } = body;
    if (!email || !senha) return err(400, "Email e senha obrigatórios");
    const { data: users } = await sb("GET", `users?email=eq.${encodeURIComponent(email)}&select=*`);
    if (!users || users.length === 0) return err(401, "Email ou senha incorretos");
    const user = users[0];
    if (user.senha !== hashSenha(senha)) return err(401, "Email ou senha incorretos");
    const mesAtual = new Date().toISOString().slice(0, 7);
    if (user.mes_referencia !== mesAtual) {
      await sb("PATCH", `users?id=eq.${user.id}`, { audios_mes: 0, mes_referencia: mesAtual });
      user.audios_mes = 0;
    }
    if (user.plano === "mensal" && user.plano_expira_em && new Date(user.plano_expira_em) < new Date()) {
      await sb("PATCH", `users?id=eq.${user.id}`, { plano: "gratuito" });
      user.plano = "gratuito";
    }
    return ok({ ok: true, user: { id: user.id, email: user.email, plano: user.plano, audios_mes: user.audios_mes, is_admin: user.is_admin } });
  }

  // POST /registrar-audio
  if (path === "registrar-audio" && req.method === "POST") {
    const { user_id } = body;
    if (!user_id) return err(401, "Não autorizado");
    const { data: users } = await sb("GET", `users?id=eq.${user_id}&select=*`);
    if (!users || users.length === 0) return err(401, "Usuário não encontrado");
    const user = users[0];
    if (user.plano === "gratuito" && user.audios_mes >= LIMITE_GRATUITO) return err(403, "Limite gratuito atingido");
    const novoTotal = (user.audios_mes || 0) + 1;
    await sb("PATCH", `users?id=eq.${user_id}`, { audios_mes: novoTotal });
    return ok({ ok: true, audios_mes: novoTotal, restante: user.plano === "gratuito" ? LIMITE_GRATUITO - novoTotal : null });
  }

  // POST /criar-pagamento
  if (path === "criar-pagamento" && req.method === "POST") {
    const { user_id, plano } = body;
    if (!user_id || !plano) return err(400, "Parâmetros obrigatórios");
    const { data: users } = await sb("GET", `users?id=eq.${user_id}&select=*`);
    if (!users || users.length === 0) return err(401, "Usuário não encontrado");
    const user = users[0];
    const planos = { mensal: { titulo: "Auto11Labs — 2 Meses", preco: 37.90 }, vitalicio: { titulo: "Auto11Labs — Vitalício", preco: 117.90 } };
    if (!planos[plano]) return err(400, "Plano inválido");
    const p = planos[plano];
    const siteUrl = process.env.SITE_URL || SITE_URL;
    const mpRes = await fetch("https://api.mercadopago.com/checkout/preferences", {
      method: "POST",
      headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        items: [{ title: p.titulo, quantity: 1, unit_price: p.preco }],
        payer: { email: user.email },
        back_urls: { success: `${siteUrl}/?pagamento=sucesso&plano=${plano}&user=${user_id}`, failure: `${siteUrl}/?pagamento=falha` },
        auto_return: "approved",
        notification_url: `${siteUrl}/api/webhook-mp`,
        metadata: { user_id, plano },
      }),
    });
    const pref = await mpRes.json();
    if (!mpRes.ok) return err(500, "Erro ao criar pagamento");
    await sb("POST", "pagamentos", { user_id, mp_preference_id: pref.id, plano, status: "pendente" });
    return ok({ ok: true, url: pref.init_point });
  }

  // POST /webhook-mp
  if (path === "webhook-mp" && req.method === "POST") {
    const { type, data } = body;
    if (type !== "payment") return ok({ ok: true });
    const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${data.id}`, { headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}` } });
    const pagamento = await mpRes.json();
    if (pagamento.status !== "approved") return ok({ ok: true });
    const userId = pagamento.metadata?.user_id;
    const plano = pagamento.metadata?.plano;
    if (!userId || !plano) return ok({ ok: true });
    const expira = plano === "mensal" ? new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString() : null;
    await sb("PATCH", `users?id=eq.${userId}`, { plano: plano === "mensal" ? "mensal" : "vitalicio", plano_expira_em: expira });
    return ok({ ok: true });
  }

  // GET /confirmar-pagamento
  if (path === "confirmar-pagamento" && req.method === "GET") {
    const { user: userId, plano } = query;
    if (!userId || !plano) return err(400, "Parâmetros inválidos");
    const expira = plano === "mensal" ? new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString() : null;
    await sb("PATCH", `users?id=eq.${userId}`, { plano: plano === "mensal" ? "mensal" : "vitalicio", plano_expira_em: expira });
    return ok({ ok: true });
  }

  // GET /admin/usuarios
  if (path === "admin/usuarios" && req.method === "GET") {
    const { admin_id } = query;
    const { data: admin } = await sb("GET", `users?id=eq.${admin_id}&select=is_admin`);
    if (!admin || !admin[0]?.is_admin) return err(403, "Acesso negado");
    const { data: users } = await sb("GET", "users?select=id,email,plano,audios_mes,plano_expira_em,criado_em,is_admin&order=criado_em.desc");
    return ok({ ok: true, users });
  }

  // POST /admin/alterar-plano
  if (path === "admin/alterar-plano" && req.method === "POST") {
    const { admin_id, user_id, plano } = body;
    const { data: admin } = await sb("GET", `users?id=eq.${admin_id}&select=is_admin`);
    if (!admin || !admin[0]?.is_admin) return err(403, "Acesso negado");
    const expira = plano === "mensal" ? new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString() : null;
    await sb("PATCH", `users?id=eq.${user_id}`, { plano, plano_expira_em: expira });
    return ok({ ok: true });
  }

  // POST /admin/resetar-uso
  if (path === "admin/resetar-uso" && req.method === "POST") {
    const { admin_id, user_id } = body;
    const { data: admin } = await sb("GET", `users?id=eq.${admin_id}&select=is_admin`);
    if (!admin || !admin[0]?.is_admin) return err(403, "Acesso negado");
    await sb("PATCH", `users?id=eq.${user_id}`, { audios_mes: 0 });
    return ok({ ok: true });
  }

  return err(404, "Rota não encontrada");
};
