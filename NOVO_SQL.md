# Execute este SQL no Supabase → SQL Editor

```sql
-- Coluna IP no cadastro (para limite por IP)
ALTER TABLE users ADD COLUMN IF NOT EXISTS ip_cadastro TEXT;

-- Tabela de logs de pagamento
CREATE TABLE IF NOT EXISTS logs_pagamento (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  tipo TEXT NOT NULL,
  dados TEXT,
  erro TEXT,
  criado_em TIMESTAMP DEFAULT now()
);

ALTER TABLE logs_pagamento ENABLE ROW LEVEL SECURITY;
CREATE POLICY "all" ON logs_pagamento FOR ALL USING (true);
```

## Projetos do VideoMix (salvar montagem na conta)

```sql
CREATE TABLE IF NOT EXISTS projetos (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  nome TEXT NOT NULL,
  dados JSONB NOT NULL,
  criado_em TIMESTAMP DEFAULT now(),
  atualizado_em TIMESTAMP DEFAULT now()
);

ALTER TABLE projetos ENABLE ROW LEVEL SECURITY;
CREATE POLICY "all" ON projetos FOR ALL USING (true);
```

## Saldo (créditos em R$) para legenda automática

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS saldo NUMERIC DEFAULT 0;
```
