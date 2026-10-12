# RMP — Protocolo (wire format)

Versão deste documento: **1**. Identificador de ALPN: **`rmp/1`**.

## 1. Princípios

- O transporte é **QUIC/TLS 1.3**: confidencialidade, integridade e autenticação de
  transporte já são garantidas por baixo.
- Streams QUIC são **confiáveis e ordenados**: o protocolo não retransmite nem reordena.
- Todo formato é **versionado desde o primeiro byte** para permitir evolução.
- Mensagens são **binárias** e codificadas com `serde` + `postcard`.

## 2. Streams

| Stream | Direção | Uso |
|---|---|---|
| Control (bidi, o primeiro aberto) | ambos | Hello, capabilities, autenticação OPAQUE, abertura/fechamento de canais, ping, disconnect |
| Session (bidi) | ambos | PTY: `Data`, resize, sinais, exit status |
| Session (bidi) | ambos | `exec` não interativo (fase posterior) |

Cada stream começa com um **preâmbulo de tipo** (`StreamKind`) para o receptor saber o que
esperar. Streams de dados (payload do PTY) usam frames do tipo `Data`.

## 3. Framing

Todo frame:

```
 0               1               2               3
 +---------------+---------------+---------------+---------------+
 |            MAGIC = 0x524D ('R','M')           |  VERSION u8   |  FRAME_TYPE u8 |
 +---------------+---------------+---------------+---------------+
 |                          LENGTH u32 (BE)                      |
 +---------------------------------------------------------------+
 |                        PAYLOAD (LENGTH bytes)                 |
 +---------------------------------------------------------------+
```

- `MAGIC` (u16, BE): `0x524D`.
- `VERSION` (u8): versão do wire format; atualmente `1`.
- `FRAME_TYPE` (u8): código da mensagem (tabelas abaixo).
- `LENGTH` (u32, BE): tamanho do payload.
- **Limite:** frames acima de um `max_frame` configurável (padrão 1 MiB) derrubam a
  conexão com `FRAME_TOO_LARGE`.

Os enums de mensagem (`FrameType`) são fixados numericamente: valores desconhecidos em um
tipo **obrigatório** causam erro; em um tipo **extensível**, são ignorados.

## 4. Control channel

### 4.1 Handshake de aplicação

| Código | Mensagem | Campos |
|---|---|---|
| `0x01` | `Hello` | `proto_version: u16`, `client_name`, `client_version` |
| `0x02` | `HelloAck` | `proto_version: u16`, `server_name`, `server_version`, `capabilities: [u32]` |
| `0x03` | `Capabilities` | `client: [u32]` (intersecção negociada com o servidor) |

Capabilities iniciais: `PTY(0)`, `EXEC(1)`, `SIGNALS(2)`, `ENROLL_KEY(3)`,
`RESUME_0RTT(4)`.

### 4.2 Autenticação (OPAQUE, RFC 9807)

A troca roda dentro do control channel, sobre transporte já cifrado.

| Código | Mensagem | Direção | Campos |
|---|---|---|---|
| `0x10` | `AuthStart` | C→S | `username`, `initial: bytes` (mensagem OPAQUE) |
| `0x11` | `AuthResponse` | S→C | `payload: bytes` (mensagem OPAQUE) |
| `0x12` | `AuthFinish` | C→S | `payload: bytes`, `device_pubkey?: bytes` |
| `0x13` | `AuthResult` | S→C | `ok: bool`, `reason: AuthReason`, `session_token?` |

`AuthReason`: `INVALID_CREDENTIALS`, `LOCKED_OUT`, `RATE_LIMITED`, `KEY_ENROLLED`,
`BANNER`.

> A senha **nunca** aparece em nenhuma mensagem. `device_pubkey` é enviado apenas no
> enrollment opcional.

### 4.3 Controle de canais

| Código | Mensagem | Campos |
|---|---|---|
| `0x20` | `ChannelOpen` | `channel_id: u32`, `kind: ChannelKind` |
| `0x21` | `ChannelOpenAck` | `channel_id: u32`, `ok: bool`, `reason?` |
| `0x22` | `ChannelClose` | `channel_id: u32`, `reason: CloseReason` |
| `0x23` | `WindowAdjust` | `channel_id: u32`, `delta_bytes: u32` |

`ChannelKind`: `Session(0)`, `Exec(1)` (futuro: `Forward(2)`, `AgentForward(3)`).

### 4.4 Liveness e encerramento

| Código | Mensagem | Campos |
|---|---|---|
| `0x30` | `Ping` | `nonce: u64` |
| `0x31` | `Pong` | `nonce: u64` |
| `0x32` | `Disconnect` | `reason: DisconnectReason`, `message: string` |
| `0x33` | `GoAway` | `last_channel: u32` (servidor em shutdown) |

## 5. Session channel

Stream bidi iniciado pelo cliente, com `channel_id` no preâmbulo.

| Código | Mensagem | Direção | Campos |
|---|---|---|---|
| `0x40` | `PtyRequest` | C→S | `term: string`, `cols: u16`, `rows: u16`, `pixel_w: u16`, `pixel_h: u16`, `modes: bytes` |
| `0x41` | `Shell` | C→S | — |
| `0x42` | `Exec` | C→S | `command: string` |
| `0x43` | `Env` | C→S | `name: string`, `value: bytes` |
| `0x44` | `WindowChange` | C→S | `cols: u16`, `rows: u16`, `pixel_w: u16`, `pixel_h: u16` |
| `0x45` | `Signal` | C→S | `signal: string` |
| `0x46` | `Data` | ambos | `data: bytes` (stdio do PTY / `stdin`) |
| `0x47` | `Eof` | C→S | — (fecha o stdin) |
| `0x48` | `ExitStatus` | S→C | `exit_code: u32`, `signal?: string` |
| `0x49` | `ExitSignal` | S→C | `signal: string`, `core_dumped: bool`, `message: string` |

Entrega do PTY: `Data` (servidor→cliente) = stdout; não há separação stderr no modo PTY
(o terminal mescla; separação fica no modo `Exec`).

## 6. Fluxo de controle (flow control)

- Além do flow control nativo do QUIC, há uma janela por canal (`WindowAdjust`) para
  limitar memória por sessão.
- Padrão inicial: 1 MiB por direção; ajustável em config.
- Estouro de janela sem crédito é erro de protocolo.

## 7. Perda de pacotes e reconexão

- **Perda/congestionamento:** delegados ao QUIC (retransmissão, PTO, CUBIC/BBR). O
  protocolo de aplicação não trata perda.
- **Idle timeout:** sem `Pong` dentro de `idle_timeout`, a conexão é encerrada; o cliente
  tenta reatar.
- **Resumption 0-RTT:** usado para retomar a sessão quando `RESUME_0RTT` foi negociado.
  0-RTT é restrito a mensagens idempotentes para evitar replay; a primeira mensagem após
  resumption não pode acionar efeitos irreversíveis.
- **Connection migration:** trocar de rede preserva a sessão via Connection ID.

## 8. Erros e códigos

`DisconnectReason`: `BYE(0)`, `PROTOCOL_ERROR(1)`, `AUTH_FAILED(2)`, `AUTH_LOCKED(3)`,
`IDLE_TIMEOUT(4)`, `FRAME_TOO_LARGE(5)`, `SERVER_SHUTDOWN(6)`, `INTERNAL(255)`.

Regras de erro:
- Frame malformado → `PROTOCOL_ERROR` e fecha a conexão.
- `FRAME_TYPE` desconhecido em contexto obrigatório → `PROTOCOL_ERROR`.
- Falha de autenticação repetida → incrementa contador; ao exceder limite, `AUTH_LOCKED`.

## 9. Extensibilidade

- `proto_version` é negociado no `Hello`/`HelloAck`; a menor versão comum é usada.
- `capabilities` permite negociação aditiva sem quebrar clientes antigos.
- Novos `FrameType` em faixas reservadas; receptores ignoram tipos desconhecidos quando
  marcado como extensível.
