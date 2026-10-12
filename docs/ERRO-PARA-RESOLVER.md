## Resumo: OpenCode Security Guard e o erro de assinatura do Claude

### 1. O problema

O plugin [opencode-security-guard](https://github.com/marioalexandreantunes/opencode-security-guard) provoca um erro quando utilizamos o Claude Haiku 5.5 através do OpenCode Go Plan:

```
Upstream request failed: [invalid_request_error]
messages.3.content.0:
Invalid `signature` in `thinking` block
```

O erro desaparece quando desativamos o plugin, o que indica uma incompatibilidade entre o processamento das mensagens pelo Security Guard e a validação dos blocos de raciocínio do Claude.

### 2. Causa provável

O Security Guard interceta e sanitiza mensagens, incluindo o histórico, para impedir que segredos sejam enviados ao modelo.

O problema surge no hook `experimental.chat.messages.transform`, que pode modificar conteúdo associado a blocos de thinking.

O Claude utiliza assinaturas criptográficas para verificar a integridade desses blocos. Quando o conteúdo assinado é alterado, a assinatura deixa de corresponder ao original e a API rejeita o pedido.

### 3. O comportamento pretendido

O objetivo do Security Guard não é bloquear o agente, mas protegê-lo de forma transparente, mantendo a execução contínua.

Queremos garantir que:

- Os segredos nunca são expostos ao modelo.
- O agente continua a trabalhar normalmente.
- As mensagens são sanitizadas sem provocar erros de assinatura.
- O mecanismo de proteção funciona com diferentes providers e modelos.
- O sistema mantém a possibilidade de restaurar segredos localmente através do vault.

### 4. Solução proposta

A solução deve distinguir entre conteúdo modificável e conteúdo criptograficamente assinado.

Para mensagens normais:

Continuar a aplicar a sanitização e a substituição de segredos por placeholders, como já acontece.

Para blocos de thinking assinados:

Não é possível modificar o conteúdo e manter a assinatura original válida. Também não é possível gerar uma nova assinatura válida sem a chave privada do provider.

A abordagem adequada será:

1. Detetar blocos de thinking assinados antes da sanitização.
2. Verificar se contêm segredos, sem modificar o conteúdo original.
3. Quando não existem segredos, preservar integralmente o bloco e a assinatura.
4. Quando existem segredos, substituir o bloco assinado por uma representação segura e não assinada, apenas se o protocolo do provider permitir essa transformação.
5. Quando essa substituição não é permitida, omitir o bloco de thinking do histórico e preservar as mensagens normais e os resultados relevantes que possam ser sanitizados.
6. Garantir que a estrutura final do histórico continua válida para o provider.

A eliminação de um bloco assinado também pode exigir ajustes ao histórico, dependendo das regras da API. Por isso, esta transformação tem de ser validada por provider.

### 5. Resultado esperado

Segurança sem interromper o agente

Mensagem / Histórico

Security Guard

Deteção e classificação do conteúdo

Conteúdo normal

Redação de segredos

Thinking assinado

Preservar ou omitir com segurança

Pedido válido ao provider

Agente continua a executar

### 6. Critério de aceitação

O plugin deve passar nos seguintes testes:

- Claude Haiku 5.5 com thinking e sem segredos.
- Claude Haiku 5.5 com segredos no histórico de mensagens normais.
- Claude Haiku 5.5 com segredos dentro de blocos de thinking assinados.
- Execução de várias ferramentas e ciclos consecutivos, sem erros de assinatura.
- Nenhuma exposição de segredos ao modelo.
- Compatibilidade com outros modelos que utilizem assinaturas ou metadados de integridade.

Conclusão: a solução não é recalcular assinaturas nem bloquear automaticamente o pedido. É aplicar uma transformação consciente do protocolo, preservando blocos assinados seguros e removendo ou substituindo os inseguros de forma que o provider aceite o histórico.

Existe, contudo, um limite importante: se o provider exigir determinado bloco assinado para continuar a conversa e não permitir a sua omissão, não há garantia de continuidade automática sem reconstruir uma sessão válida. Nesse cenário, uma recuperação controlada numa nova sessão, com contexto sanitizado, é preferível a enviar segredos ou assinaturas inválidas.

Princípio de arquitetura: Sanitize what is mutable, preserve what is signed, reconstruct what cannot safely be preserved.