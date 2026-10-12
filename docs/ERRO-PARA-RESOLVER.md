## Resumo: OpenCode Security Guard e o erro de assinatura do Claude

### 1. O problema

O plugin [opencode-security-guard](https://github.com/marioalexandreantunes/opencode-security-guard) provoca um erro quando utilizamos o Claude Haiku 5.5 através do OpenCode Go Plan:

```
Upstream request failed: [invalid_request_error]
messages.3.content.0:
Invalid `signature` in `thinking` block
```

O erro desaparece quando desativamos o plugin. Ocorre mesmo sem segredos reais no histórico.

### 2. Causa (confirmada no código)

O hook `experimental.chat.messages.transform` (`src/plugin.ts`) chama `redactSkipping` sobre todas as chaves de cada `part`, exceto as de estrutura (`PART_SKIP`: `id`, `type`, `time`, `tokens`, etc.). Isto inclui o `metadata` das partes `reasoning`, onde o Claude guarda a `signature`.

A regra `entropy-blob` (`src/rules.ts`) deteta strings de 40 a 512 caracteres `[A-Za-z0-9+=_-]` com maiúsculas, minúsculas, dígitos e entropia suficiente. As assinaturas do Claude cumprem estes critérios.

Teste isolado realizado:

```
thinking signature: <SECURITY_GUARD_REDACTED:entropy-blob:767ffffc3c4abbf0>
```

Ou seja, a assinatura é reescrita mesmo quando não existe nenhum segredo. A API valida a assinatura e rejeita o pedido.

Não existe hoje nenhuma verificação "este bloco tem segredo?" antes da redação.

### 3. O comportamento pretendido

O Security Guard não deve bloquear o agente, mas proteger o conteúdo de forma transparente.

- Os segredos nunca são expostos ao modelo.
- O agente continua a trabalhar normalmente.
- As mensagens são sanitizadas sem provocar erros de assinatura.
- O mecanismo funciona com diferentes providers e modelos.
- Os segredos continuam recuperáveis localmente através do vault.

### 4. Solução proposta (ainda não implementada)

Distinguir conteúdo modificável de conteúdo assinado.

Para mensagens normais: manter a sanitização e a substituição de segredos por placeholders.

Para blocos `reasoning` com assinatura:

1. Não redigir a assinatura (`signature`, `redactedData`), em nenhuma profundidade. Qualquer alteração invalida a assinatura, mesmo um falso positivo.
2. Se o texto do thinking não tiver segredos, preservar o bloco inteiro.
3. Se o texto do thinking tiver segredos, não é possível redigi-lo sem invalidar a assinatura. Omitir o bloco do histórico.
4. Confirmar que a estrutura final do histórico continua válida para o provider. Omitir um bloco de thinking pode exigir ajustes, dependendo das regras da API.

Alterações previstas (não implementadas, a pedido: só documentação):

- `src/redact.ts`: opção para ignorar chaves opacas.
- `src/plugin.ts`: tratamento de `reasoning` no `messages.transform`.
- `tests/security-guard/chat-hooks.test.mts`: testes para assinatura preservada e bloco com segredo omitido.

### 5. Resultado esperado

Mensagem / Histórico → Security Guard → Deteção e classificação

- Conteúdo normal → redação de segredos
- Thinking com assinatura, sem segredos → preservar assinatura
- Thinking com assinatura, com segredos → omitir bloco

→ Pedido válido ao provider → agente continua a executar

### 6. Critérios de aceitação (estado atual)

- [ ] Claude Haiku 5.5 com thinking e sem segredos: **falha hoje** (causa confirmada, correção não implementada).
- [ ] Claude Haiku 5.5 com segredos no histórico de mensagens normais: a redação existe; não validada contra a API real.
- [ ] Claude Haiku 5.5 com segredos dentro de blocos de thinking assinados: a omissão ainda não está implementada.
- [ ] Execução de várias ferramentas e ciclos consecutivos, sem erros de assinatura: não validado.
- [ ] Nenhuma exposição de segredos ao modelo: não validado de ponta a ponta.
- [ ] Compatibilidade com outros modelos que utilizem assinaturas: não validado.

### Conclusão

A solução não é recalcular assinaturas nem bloquear o pedido. Consiste em não tocar nas assinaturas, e em omitir apenas os blocos de thinking cujo texto contém segredos.

Limite importante: se o provider exigir um bloco assinado específico para continuar a conversa e não permitir a sua omissão, não há continuidade automática sem reconstruir uma sessão válida. Nesse caso, uma recuperação controlada numa nova sessão, com contexto sanitizado, é preferível a enviar segredos ou assinaturas inválidas.

Princípio de arquitetura: Sanitize what is mutable, preserve what is signed, reconstruct what cannot safely be preserved.
