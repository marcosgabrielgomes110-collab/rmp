# RMP — Arquitetura

> RMP (Remote Machine Protocol) é um protocolo de acesso remoto por terminal, no estilo
> SSH: após autenticação, o cliente recebe um PTY interativo na máquina remota.

## 1. Objetivos

- **Seguro por padrão:** nenhum texto claro na rede, autenticação resistente a ataques de
  dicionário, verificação de identidade do servidor.
- **Rápido:** multiplexação de streams, handshake 1-RTT, resumption 0-RTT, sem
  head-of-line blocking.
- **Robusto em redes ruins:** retransmissão e controle de congestionamento tratam perda de
  pacotes; a sessão sobrevive a troca de rede (connection migration).
- **Fácil de usar:** setup pede uma senha; conectar é `rmp connect user@host`.
- **Multiplataforma:** servidor e cliente em Linux, macOS e Windows.

### Não-objetivos (no MVP)

- Relays / NAT traversal / hole punching (o design deixa gancho, mas não implementa).
- SFTP e port forwarding (previstos, não no MVP).
- Federação de identidade / SSO.

## 2. Pilha de protocolo

```
┌─────────────────────────────────────────────┐
│  rmp-cli          init | serve | connect     │
├─────────────────────────────────────────────┤
│  rmp-client / rmp-server                     │
│    canais de sessão (PTY, exec), controle    │
├─────────────────────────────────────────────┤
│  rmp-crypto                                  │
│    OPAQUE (aPAKE) · host keys Ed25519        │
│    Argon2id · known_hosts (TOFU)             │
├─────────────────────────────────────────────┤
│  rmp-proto                                   │
│    framing versionado, mensagens, ALPN       │
├─────────────────────────────────────────────┤
│  QUIC (quinn)                                │
│    streams · loss recovery · congestion      │
├─────────────────────────────────────────────┤
│  TLS 1.3 (rustls)                            │
│    X25519+ML-KEM-768 · AEAD · ALPN           │
├─────────────────────────────────────────────┤
│  UDP                                         │
└─────────────────────────────────────────────┘
```

O QUIC é a fronteira de confiabilidade: **todo stream é confiável e ordenado**. A
aplicação não implementa retransmissão; ela apenas reage a erro de conexão.

## 3. Componentes

| Crate | Responsabilidade |
|---|---|
| `rmp-proto` | Wire format, versionamento, definição das mensagens, ALPN `rmp/1`, codecs. |
| `rmp-dirs` | Layout de diretórios (XDG para usuário, FHS para serviço). |
| `rmp-crypto` | Configuração TLS 1.3 + PQC, gestão de host keys, sub-protocolo OPAQUE, Argon2id, `known_hosts`. |
| `rmp-server` | Listener QUIC, autenticação, ciclo de vida de sessões, spawn de PTY, políticas (rate limit/lockout), audit log. |
| `rmp-client` | Conexão, verificação de host key, login, abertura de canal de sessão, I/O do terminal. |
| `rmp-cli` | Subcomandos `init`, `serve`, `connect`; config TOML; logging; prompts. |

## 4. Estabelecimento de conexão

1. **Descoberta/ALPN.** Cliente abre QUIC para a porta UDP de RMP e negocia ALPN `rmp/1`.
2. **Handshake TLS 1.3.** Chaves efêmeras X25519 + ML-KEM-768. O servidor apresenta seu
   certificado autoassinado derivado da **host key Ed25519**.
3. **Verificação de host key (TOFU).** O cliente compara a fingerprint com `known_hosts`.
   - Primeira conexão: mostra a fingerprint e pede confirmação (TOFU).
   - Divergência: aborta com alerta forte (possível MITM), salvo modo `strict=off`.
4. **Autenticação (OPAQUE).** Sobre o stream de controle, cliente e servidor executam a
   aPAKE. A senha nunca trafega; o servidor só guarda um registro que resiste a ataque de
   dicionário offline.
5. **Enrollment (opcional).** No primeiro login bem-sucedido, o servidor pode oferecer
   registrar uma chave de dispositivo do cliente para logins futuros sem senha.
6. **Abertura de canais.** O cliente pede um canal de sessão e um PTY; o servidor faz
   spawn do shell de login e conecta o PTY ao stream.

### Diagrama

```
Cliente                                   Servidor
  │  QUIC Initial (ALPN rmp/1)               │
  ├────────────────────────────────────────►│
  │  TLS 1.3 handshake (X25519+ML-KEM-768)   │
  │◄────────────────────────────────────────►│
  │  verifica host key (TOFU/known_hosts)    │
  │  control: Hello / Capabilities           │
  ├────────────────────────────────────────►│
  │  OPAQUE: AuthRequest ───────────────────►│
  │◄───────────────────────────── AuthResponse│
  │  control: AuthResult(ok)                 │
  │◄────────────────────────────────────────►│
  │  session: PtyRequest { term, w, h }      │
  ├────────────────────────────────────────►│
  │  session: Data ⇄ Data  (term bidirecional)│
  │◄────────────────────────────────────────►│
```

### Chave de dispositivo (login sem senha)

No primeiro acesso por senha o cliente pode registrar uma chave **Ed25519** do
dispositivo: a chave pública vai em `AuthFinish.device_pubkey`, o servidor grava em
`authorized_keys` (modo `0600`) e responde `AuthResult.key_enrolled`. Nos acessos
seguintes a autenticação é por desafio:

```
C→S  KeyAuthRequest   { username, public_key }
S→C  KeyAuthChallenge { nonce }               # sempre enviado (não vaza chaves)
C→S  KeyAuthProof     { signature }           # Ed25519 sobre usuário+chave+nonce
S→C  AuthResult       { ok }
```

A assinatura usa `rmp_proto::key_auth_context` (domínio `rmp-keyauth-v1`), ligando-a ao
usuário, à chave e a um nonce novo — impedindo replay e confusão entre contas. O servidor
só aceita chaves presentes em `authorized_keys` do usuário configurado; o login por chave
e o enrollment podem ser desligados (`[auth] allow_key_auth`, `[auth] allow_key_enrollment`).

## 5. Ciclo de vida da sessão

- **Abertura:** `ChannelOpen(type=session)` seguido de `PtyRequest` + `Shell` (ou `Exec`).
- **Interação:** `Data` trafega bytes do PTY nos dois sentidos; `WindowChange` envia
  resize; `Signal` envia Ctrl-C e afins; `ExitStatus` encerra.
- **Keepalive:** `Ping`/`Pong` periódicos; idle timeout configurável detecta links mortos.
- **Reconexão:** resumption 0-RTT reata a sessão quando o transporte cai; 0-RTT só é usado
  para operações idempotentes, prevenindo replay.
- **Encerramento:** `Disconnect { reason }` propaga motivo; o servidor faz cleanup do PTY
  e do processo filho.

## 6. Cross-platform

| Aspecto | Linux / macOS | Windows |
|---|---|---|
| PTY | `portable-pty` (openpty) | `portable-pty` (ConPTY) |
| Shell padrão | login shell do usuário (`$SHELL`, senão `/bin/sh`) | `cmd.exe` (ou `pwsh.exe` configurável) |
| Resize | `TIOCSWINSZ` + `SIGWINCH` | `ResizePseudoConsole` |
| Sinais | sinais POSIX por sessão/processo | injeção de Ctrl-C no ConPTY |
| Credenciais | permissões `0600` | ACL / DPAPI |
| Serviço | systemd | launchd / SCM |

Toda a diferença fica atrás de uma camada `pty`/`signal` em `rmp-server`, mantendo o
protocolo idêntico entre plataformas.

## 7. Diretórios e configuração

Os arquivos são separados conforme a função (XDG para uso do usuário, FHS para
serviço do sistema). Diretórios criados com modo `0700`; arquivos sensíveis com `0600`.

| Tipo | Usuário (XDG) | Sistema (`--system`) |
|---|---|---|
| Config (`config.toml`, `known_hosts`) | `~/.config/rmp` | `/etc/rmp` |
| Dados / segredos (host key, OPAQUE, hashes) | `~/.local/share/rmp` | `/var/lib/rmp` |
| Estado / logs | `~/.local/state/rmp` | `/var/log/rmp` |

Arquivo TOML (`<config>/config.toml`, gerado comentado por `rmp init`):

```toml
[server]
enabled = true            # false → o daemon recusa iniciar
listen = "0.0.0.0:2222"
username = "alice"
shell = ""                # "" = $SHELL / padrão
motd = ""
max_sessions = 8

[auth]
password_enabled = true   # false → nenhuma autenticação por senha
allow_root = false        # login root (exige o servidor rodando como root)
max_auth_attempts = 5
lockout_secs = 30

[security]
allowed_cidrs = ["0.0.0.0/0", "::/0"]
denied_cidrs = []         # tem precedência sobre allowed_cidrs
idle_timeout_secs = 600
keep_alive_secs = 15

[logging]
enabled = true
level = "info"
audit = true
log_commands = true
log_dir = ""

[client]
strict_host_key = true
accept_new_hosts = false
connect_timeout_secs = 10
idle_timeout_secs = 600
```

### Port forwarding

Uma stream de encaminhamento começa com `ForwardRequest`; o lado que recebe a mensagem
disca a conexão TCP de destino, responde `ForwardResponse{ok}` e então transporta os bytes
em ambos os sentidos via mensagens `Data` (terminadas por `Eof`). Em `rmp connect -L
port:host:port`, o cliente cria o listener TCP local e o servidor abre a conexão de
destino. O servidor pode desligar isso com `[server] allow_local_forward`.

### Modo root

Com `[auth] allow_root = true`, o servidor **exige rodar como root** (senão recusa
iniciar). Nesse modo, logins do usuário comum são **rebaixados via `runuser`** — um login
normal nunca recebe shell de root; apenas o login `root` (com a senha root, registrada à
parte em `password_file.root.bin`) obtém shell privilegiado.


### Logs

Dois arquivos com rotação diária no diretório de estado:

- `rmp.log.<data>` — tudo (console + eventos internos dos crates RMP);
- `audit.log.<data>` — **somente** eventos de segurança (target `rmp::audit`),
  independente de `RUST_LOG`.

Eventos auditados: `server.start/stop`, `handshake.ok`, `auth.attempt/success/failure/lockout`,
`session.open/close`, `connection.close`; no cliente `client.connect`, `host.trusted/mismatch/rejected`,
`auth.success`, `session.start/end`. Nenhum segredo é registrado.


## 8. Referências internas

- `protocol.md` — wire format e mensagens.
- `threat-model.md` — ativos, adversários, garantias e mitigações.
