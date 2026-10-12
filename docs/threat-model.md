# RMP — Modelo de ameaças

## 1. Ativos

| Ativo | Sensibilidade |
|---|---|
| Senha de acesso remoto | Crítica |
| Host key privada (Ed25519) | Crítica |
| Chave de dispositivo do cliente, quando cadastrada | Crítica |
| Bytes do PTY (comandos, saída, segredos digitados no shell) | Alta |
| Registro OPAQUE da senha no servidor | Alta (deve resistir a ataque offline) |
| `known_hosts` (fingerprints) | Média (integridade) |
| Metadados de conexão (IP, horário, duração) | Baixa/Média |

## 2. Adversários considerados

1. **Rede passiva (sniffing):** observa tráfego, tenta ler conteúdo ou metadados.
2. **MITM ativo:** intercepta, injeta, reordena, faz downgrade de cripto.
3. **Brute force de senha:** muitas tentativas online contra a autenticação.
4. **Ataque offline ao servidor comprometido:** rouba o arquivo de senha/registro OPAQUE e
   tenta quebrar a senha sem tocar a rede.
5. **DoS / amplificação:** esgota recursos ou usa o servidor como amplificador.
6. **Adversário com "store now, decrypt later" (quântico):** grava tráfego hoje para
   decifrar no futuro.
7. **Local malicioso no cliente:** tenta reusar credenciais capturadas.
8. **Físico / roubo de dispositivo:** copia arquivos de chave do disco.

## 3. Garantias

- **Confidencialidade e integridade** de todo o tráfego de aplicação: TLS 1.3 obrigatório,
  cada pacote é AEAD (AES-256-GCM ou ChaCha20-Poly1305). Não há modo sem criptografia nem
  downgrade.
- **Forward secrecy:** chaves efêmeras por conexão.
- **Resistência pós-quântica** ao "store now, decrypt later": handshake híbrido
  X25519 + ML-KEM-768 por padrão.
- **A senha nunca trafega:** autenticação OPAQUE (aPAKE).
- **Resistência offline:** um servidor comprometido guarda apenas o registro OPAQUE, sobre
  o qual ataques de dicionário exigem o mesmo custo de um brute force online por conta.
- **Autenticidade do servidor:** host key Ed25519 com TOFU / `known_hosts` estrito.
- **Anti-replay de pacotes:** números de pacote e proteções do QUIC.
- **Anti-DoS básico:** address validation + Retry tokens do QUIC; limites de conexão.

## 4. Não-garantias (explícitas)

- **Host key não é CA-assinada:** a confiança inicial é TOFU. Um MITM **na primeira**
  conexão pode se passar pelo servidor; por isso exige-se verificação fora de banda da
  fingerprint quando possível.
- **Sem atestação de endpoint:** não há garantia de que o dispositivo do cliente está
  íntegro (sem TPM/attestation no MVP).
- **Metadados de rede visíveis:** IPs e volumes de tráfego são observáveis; RMP não faz
  padding/obfuscação de tráfego no MVP.
- **Sessão 0-RTT:** reduz garantias contra replay se usada para operações com efeito; o
  protocolo restringe 0-RTT a operações idempotentes.
- **Segurança depende da força da senha:** OPAQUE eleva o custo de ataque, mas uma senha
  fraca continua adivinhável online.

## 5. Mitigações por ameaça

| Ameaça | Mitigação |
|---|---|
| Sniffing | TLS 1.3 + AEAD em todos os pacotes |
| MITM / downgrade | TLS 1.3 obrigatório; sem cipher-suites fracas; host key verificada |
| Brute force online | Rate limiting, backoff exponencial, lockout por usuário/IP; Argon2id como KSF |
| Ataque offline ao registro | OPAQUE (registro não permite testar senhas sem interação) |
| DoS / amplificação | QUIC Retry/address validation, limites de conexão e de frame |
| "Store now, decrypt later" | Handshake híbrido X25519 + ML-KEM-768 |
| Reuso de credenciais no cliente | Chave de dispositivo só destrava localmente com Argon2id; sem envio da senha |
| Roubo de disco | Chaves privadas `0600`/DPAPI; `zeroize` em memória; sem segredos em log |

## 6. Rate limiting e lockout

- Contador de tentativas por `(usuário, IP)` e global.
- Backoff exponencial; lockout temporário após `max_auth_attempts` (padrão 5).
- Respostas de falha indistinguíveis entre "usuário inexistente" e "senha errada" para não
  vazar existência de contas.

## 7. Criptografia — escolhas e justificativa

| Elemento | Escolha | Motivo |
|---|---|---|
| KEX | X25519 + ML-KEM-768 (híbrido) | Segurança clássica + PQC sem depender de um só |
| AEAD | AES-256-GCM (AES-NI) / ChaCha20-Poly1305 | Ambos AEAD; ChaCha é rápido sem aceleração de HW |
| Host key | Ed25519 | Compacta, rápida, amplamente auditada |
| Derivação de senha | Argon2id | Resistente a GPU/ASIC; parâmetros calibráveis |
| PAKE | OPAQUE (RFC 9807) | Senha nunca trafega; resiste a ataque offline |
| Zeroização | `zeroize` | Limita janela de exposição em memória |
| Comparação | `subtle` (tempo constante) | Evita side-channel de timing |

## 8. Princípios de implementação

- **Memory-safe:** Rust com `#![forbid(unsafe_code)]` sempre que possível; dependências de
  cripto bem auditadas (`rustls`, `ring`/`aws-lc-rs`, `argon2`, `opaque-ke`).
- **Nenhum segredo em log:** trilhas de auditoria registram eventos, nunca material secreto.
- **Fail closed:** qualquer erro de parsing/negociação encerra a conexão.
- **Versionamento seguro:** versão/negociação explícitas para recusar combinações inseguras.

## 9. Auditoria e logging

RMP mantém uma trilha de auditoria dedicada, separada do log operacional, para permitir
detecção e resposta a incidentes.

- **`audit.log`** (rotação diária, `0600`, diretório de estado `0700`): registra
  `server.start/stop`, `handshake.ok`, `auth.attempt/success/failure/lockout`,
  `session.open/close`, `connection.close`; no cliente `client.connect`,
  `host.trusted/mismatch/rejected`, `auth.success`, `session.start/end`.
- **`rmp.log`**: log operacional completo (console + eventos internos), com filtro
  configurável por `RUST_LOG`.
- **Contra a evasão de log:** uma tentativa de autenticação abortada pelo cliente
  (o caso típico de senha errada em OPAQUE, que o cliente detecta localmente) é
  registrada pelo servidor como `auth.failure reason="aborted"` e **conta para o
  rate limit** — o servidor não deixa a tentativa "invisível".
- **Sem vazamento de segredos:** senhas, chaves privadas e session keys nunca são
  escritas em log; apenas identificadores não sensíveis (IP, usuário, fingerprint,
  comando executado).

Limitação honesta: `session.open` do tipo `exec`/`pty` registra o comando digitado, que
pode conter dados sensíveis fornecidos pelo usuário; trate o `audit.log` como material
sensível (por isso ele fica em diretório `0700`). O registro de comandos pode ser
desligado com `[logging] log_commands = false`.

## 10. Modo root e rebaixamento de privilégio

- `[auth] allow_root = true` habilita autenticação como `root`, com uma **senha root
  separada** (registro OPAQUE próprio em `password_file.root.bin`).
- **Fail-closed:** o servidor se recusa a iniciar se `allow_root = true` e ele não
  estiver rodando como root — assim nunca há uma promessa de root que não pode ser
  cumprida com segurança.
- **Rebaixamento obrigatório:** quando o servidor roda como root, logins do usuário
  comum são executados via `runuser -u <username> -- <shell>`, de forma que **um login
  normal nunca recebe shell de root**. Somente o login `root` (senha root + `allow_root`)
  obtém um shell privilegiado.
- A seleção do processo a executar é derivada do principal autenticado (`User`/`Root`),
  não de dados enviados pelo cliente.

