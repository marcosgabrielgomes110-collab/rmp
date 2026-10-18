# RMP — Arquitetura

> RMP (Remote Machine Protocol) é um protocolo de acesso remoto por terminal, no estilo
> SSH: após autenticação, o cliente recebe um PTY interativo na máquina remota.

## 1. Objetivos

- **Seguro por padrão:** nenhum texto claro na rede, autenticação resistente a ataques de
  dicionário, verificação de identidade do servidor.
- **Rápido:** multiplexação de streams, handshake 1-RTT, sem head-of-line blocking.
  Resumption 0-RTT não é usado para sessões de aplicação.
- **Robusto em redes ruins:** retransmissão e controle de congestionamento tratam perda de
  pacotes; a sessão sobrevive a troca de rede (connection migration).
- **Fácil de usar:** setup pede uma senha; conectar é `rmp connect user@host`.
- **Multiplataforma:** servidor e cliente em Linux, macOS e Windows.

### Não-objetivos (nesta versão)

- Relays / NAT traversal / hole punching (o design deixa gancho, mas não implementa).
- SFTP (há transferência de arquivos própria via `rmp cp`, inclusive recursiva).
- Agent/X11 forwarding, SSO e multi-usuário (single-account por servidor).
- Reconexão automática / resumption 0-RTT de sessões (as mensagens e capacidades
  existem, mas a retomada ainda não está implementada).

## 2. Pilha de protocolo

```
┌─────────────────────────────────────────────┐
│  rmp-cli    init | serve | connect | exec    │
│             cp | passwd | keys | config      │
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
| `rmp-cli` | Subcomandos `init`, `serve`, `connect`, `exec`, `cp`, `passwd`, `keys`, `known-hosts`, `config-check`; config TOML; logging; prompts. |

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

- **Abertura:** o cliente abre um stream bidi e envia `PtyRequest` + `Shell` (ou `Exec`).
  Não há `ChannelOpen`: cada sessão é um stream QUIC próprio.
- **Interação:** `Data` trafega bytes do PTY nos dois sentidos; `WindowChange` envia
  resize; `Signal` envia Ctrl-C e afins; `ExitStatus` encerra.
- **Keepalive:** `Ping`/`Pong` periódicos no canal de controle durante sessões
  interativas; o cliente encerra com erro se o servidor parar de responder. O idle
  timeout do QUIC continua valendo como segunda camada.
- **Reconexão:** não implementada nesta versão. `RESUME_0RTT` é apenas uma capacidade
  reservada; a sessão é encerrada se o transporte cair.
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
max_connections = 128
allow_local_forward = true
allow_remote_forward = false
allow_privileged_ports = false  # -R em portas <1024 no root mode (opt-in)
allow_file_transfer = true

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
format = "text"           # text | json (arquivos; console continua texto)
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
em ambos os sentidos via mensagens `Data` (terminadas por `Eof`).

- **`-L` (local):** o cliente cria o `TcpListener` local; a cada conexão ele abre uma
  stream e envia `ForwardRequest{host,port}`; o servidor disca. Gate
  `[server] allow_local_forward`.
- **`-R` (remoto):** o cliente envia `RemoteForwardBind{bind_port,target_host,target_port}`
  pelo canal de controle; o servidor faz bind em `127.0.0.1:bind_port` e responde
  `RemoteForwardBindResult{bound_port}`. A cada conexão recebida, o **servidor** abre uma
  stream para o cliente e envia `ForwardRequest{target_host,target_port}`; o **cliente**
  disca e faz o pipe. Gate `[server] allow_remote_forward` (padrão `false`; bind só em
  loopback).

### Modo root

Com `[auth] allow_root = true`, o servidor **exige rodar como root** (senão recusa
iniciar). Nesse modo, logins do usuário comum são **rebaixados via `runuser -l`** — um
login normal nunca recebe shell de root; apenas o login `root` (com a senha root,
registrada à parte em `password_file.root.bin`) obtém shell privilegiado. Enquanto o
daemon roda como root, `rmp cp` e port forwarding local (`-L`) de logins comuns são
executados por um **helper** (`runuser -l <user> -- rmp __helper`), com as credenciais
do usuário; port forwarding remoto (`-R`) é permitido em portas altas (>= 1024) nesse
modo. Portas privilegiadas exigem `[server] allow_privileged_ports = true`; o daemon
(root) faz o bind e o tráfego vai para o cliente. `root` não pode ser usado como
`server.username`.


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
