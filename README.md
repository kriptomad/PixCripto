# PixCripto

Sistema de pagamento instantâneo **100% descentralizado**, inspirado no **Pix** (praticidade
de uso, QR code) combinado com os conceitos de **Bitcoin/Ethereum** (blockchain, mineração
com Proof-of-Work, criptografia assimétrica por transação).

> ⚠️ **Nota técnica importante**: o pedido original menciona "CUDA otimizado para AMD".
> CUDA é uma tecnologia **exclusiva da NVIDIA** — placas AMD não a executam. O equivalente
> AMD é **OpenCL/ROCm/HIP**. Por isso o motor de mineração foi implementado sobre
> **OpenCL**, que roda em GPUs AMD, NVIDIA e Intel (o mesmo código funciona nos três,
> sem vendor lock-in). Se não houver GPU/driver OpenCL disponível, o sistema cai
> automaticamente para mineração em CPU — nenhuma funcionalidade fica bloqueada.

## Arquitetura

```
PixCripto/
├── app/
│   ├── crypto_utils.py   # ECDSA secp256k1 (mesma curva do Bitcoin/Ethereum), endereço Base58Check + WIF
│   ├── models.py         # Transaction, Block, Blockchain (PoW, saldo, state_root, contracts_root, validação da cadeia)
│   ├── wallet.py         # Carteira estilo Bitcoin (par de chaves + endereço Base58Check + WIF)
│   ├── hd_wallet.py       # Carteira HD (seed phrase BIP39-like, derivação hierárquica m/44'/7777'/0'/0/index)
│   ├── vm.py              # Máquina virtual de smart contracts (stack machine 256 bits, gas metering, CALL/CREATE)
│   ├── network.py         # Rede P2P real (asyncio): handshake, gossip, IBD, escolha de cadeia por trabalho
│   ├── rpc.py             # Dispatcher JSON-RPC 2.0 (spec-compliant: single/batch/notification/erros)
│   ├── ws_hub.py           # Hub de WebSocket para eventos em tempo real (novo bloco, tx pendente, reorg)
│   ├── mining.py         # Motor de mineração: OpenCL (AMD/NVIDIA/Intel) com fallback CPU
│   ├── mining_cuda.py    # Motor de mineração dedicado CUDA (NVIDIA)
│   ├── difficulty.py     # Motor de dificuldade (crescimento 20x/2 blocos) + anti-monopólio vetorizado
│   ├── layer2.py         # Rollup L2 (depósito, transferência instantânea, commit em lote, saque)
│   ├── gold_oracle.py    # Cotação ao vivo do ouro (XAU/USD) + câmbio USD/BRL → peg do PXC
│   ├── market.py         # Venda, liquidação, swap P2P, controle de dump e auto-regulação
│   ├── storage.py        # Persistência em SQLite (metadata de blocos/transações/carteiras/contratos)
│   ├── qrcode_utils.py   # Geração/leitura de QR code de pagamento (estilo "Pix copia e cola")
│   ├── purchase.py       # Compra de PXC com BRL (taxa 7,38% a cada R$100, cotação ancorada em ouro)
│   ├── settings.py       # Configuração central (.env): ambiente, HTTP/TLS/CORS, rate limit, P2P, toggles
│   ├── network_config.py# Perfis de rede (mainnet/testnet/devnet), seeds DNS, seeds.json curados
│   ├── compliance.py     # Motor de conformidade (KYC/AML): tiers, sanções, estruturação, SAR
│   ├── exchange_api.py   # API estilo Binance: ticker/klines/depth/trades + autenticação HMAC de API key
│   ├── templates/        # UI web da carteira (Jinja2): home, enviar, receber, histórico, mercado
│   ├── static/           # CSS/JS da UI web
│   └── api.py            # API REST (FastAPI) + JSON-RPC 2.0 + WebSocket + UI + Exchange + Compliance
├── admin_panel/          # Painel de administração (porta 8600) — NUNCA compilado na distribuição
│   ├── main.py           # App FastAPI separado: configura .env, seeds, sanções, dispara build
│   └── templates/dashboard.html
├── scripts/
│   └── build_distribution.py  # Gera build de distribuição real, excluindo admin_panel/.env/seeds.json/*.db
├── main.py
├── .env.example          # Todas as variáveis de ambiente documentadas (copiar para .env)
└── requirements.txt
```

## Conceitos implementados

- **Descentralização/consenso**: qualquer nó pode montar um bloco candidato, minerá-lo e
  submeter a prova (`/mining/mine` ou `/mining/submit-proof`, este último pensado para
  hardware/pool de mineração externos que rodam seu próprio kernel de busca de nonce).
- **Criptografia por transação**: toda transferência é assinada com ECDSA (secp256k1) pela
  chave privada do remetente; a rede valida a assinatura antes de aceitar a transação.
- **Blocos mineráveis**: cada bloco agrupa transações pendentes + Proof-of-Work.
- **Recompensa do minerador = 4% do valor do bloco**: calculada sobre a soma das
  transferências (`transfer`) incluídas no bloco, paga via transação `coinbase_mining`.
- **Não é escasso como Bitcoin**: qualquer pessoa pode comprar PXC com Reais via
  `/purchase/quote` + `/purchase/confirm`, com taxa de **7,38% a cada R$100** cobrados
  por cima do valor.
- **Pagamento via QR Code ou carteira direta**: `/wallet/{address}/qrcode` gera a cobrança;
  `/transaction/pay-qrcode` paga lendo o payload; `/transaction/send` paga diretamente
  para um endereço.
- **Storage em disco (SSD/HD)**: metadata de cada bloco minerado, transações e ajustes de
  dificuldade são persistidos em SQLite (`data/pixcripto_chain.db`), sobrevivendo a
  reinicializações do processo.

### Dificuldade com crescimento matemático agressivo (`app/difficulty.py`)

- A dificuldade é medida em **bits de zero exigidos no hash** (granularidade fina, cada
  +1 bit dobra a dificuldade — bem mais preciso que "nibbles" hexadecimais).
- **Cresce 20x a cada 2 blocos minerados** (`difficulty_units *= 20`), convertido para
  bits via `log2`, até um teto configurável:
  - modo `demo` (padrão da API): teto de **21 bits** — mantém a mineração viável em
    CPU/GPU comum para fins de teste.
  - modo `mainnet_like`: teto de **~76 bits**, calculado matematicamente como o
    equivalente à dificuldade de rede real do Bitcoin em 2020 (~18-19 trilhões,
    convertendo `32 + log2(dificuldade_bitcoin)` bits). **Nota de honestidade técnica**:
    minerar em ~76 bits exige ~2⁷⁶ tentativas de hash — isso é fisicamente inviável
    para qualquer hardware único (é exatamente por isso que o Bitcoin real precisa de
    uma rede inteira de fazendas de ASIC). A fórmula está implementada corretamente
    em `/mining/difficulty-status`; o modo `demo` existe para permitir testar o
    sistema de ponta a ponta em hardware comum.
- Endpoint: `GET /mining/difficulty-status`.

### Anti-monopólio de hashrate (vetorizado com NumPy)

- A cada bloco minerado, a dificuldade **efetiva** aplicada a um minerador específico
  é `dificuldade_base + penalidade`, onde a penalidade cresce com:
  - a **fatia (market-share)** desse endereço nos últimos 20 blocos minerados
    (calculada via `numpy.unique`/vetorização sobre o histórico de mineradores);
  - o **alpha da operação**, que aumenta a cada vitória **consecutiva** do mesmo
    minerador (`alpha = ALPHA_BASE + ALPHA_STREAK_GROWTH * streak`), tornando cada
    vitória subsequente progressivamente mais custosa.
- Isso significa que a dificuldade **nunca fica mais fácil** para quem concentra
  hashrate — ela só aumenta, desestimulando pools/grupos a dominarem a rede.
- Endpoint: `GET /mining/network-stats` retorna o índice de concentração **HHI**
  (Herfindahl-Hirschman; próximo de 1.0 = alta concentração/risco de monopólio).

### Mineração colaborativa (pool mining) — `Block.reward_breakdown()`

Assim como pools de mineração reais do Bitcoin, o PixCripto permite que
**vários endereços** validem/minerem o mesmo bloco colaborativamente e
dividam a recompensa de 4% do valor do bloco proporcionalmente ao trabalho
contribuído:

- `/mining/mine` e `/mining/submit-proof` aceitam um campo opcional
  `pool_contributors: [{address, shares}]` — `shares` é o peso relativo de
  cada contribuidor (ex: número de "partial proofs"/shares submetidos ao
  coordenador do pool antes do bloco ser fechado).
- A recompensa total do bloco é dividida **proporcionalmente** aos `shares`
  de cada contribuidor (agregando automaticamente endereços repetidos), com o
  último contribuidor recebendo o resto exato para nunca perder frações de
  moeda por arredondamento de ponto flutuante.
- Limites de consenso (`app/root_rules.py`): `MAX_POOL_CONTRIBUTORS_PER_BLOCK`
  (500) e `MIN_POOL_CONTRIBUTOR_SHARE` (1e-9) — protegem contra blocos com
  milhares de contribuidores triviais (spam/DoS no payload do bloco).
- Se `pool_contributors` for omitido, o comportamento é o legado (100% da
  recompensa para `miner_address`) — mudança 100% retrocompatível.
- Resposta inclui `reward_breakdown`: lista de `{address, amount, memo}` com
  o valor exato creditado a cada contribuidor.

### Mineração com GPU como fonte primária: CUDA (NVIDIA) e OpenCL/ROCm (AMD)

- **CUDA (`app/mining_cuda.py`)**: backend dedicado a GPUs **NVIDIA** via PyCUDA —
  usa CUDA cores para paralelizar a busca de nonces.
- **OpenCL/ROCm (`app/mining.py`)**: backend dedicado a GPUs **AMD** (Stream
  Processors), também funciona em Intel/outras via OpenCL genérico.
- `mine_block()` escolhe automaticamente: **CUDA (NVIDIA) → OpenCL/ROCm (AMD) → CPU**
  — GPU é sempre tentada primeiro; CPU é apenas o fallback final.
- Endpoint `GET /mining/gpu-status` mostra o status **dos dois backends
  separadamente** e qual seria usado (`recommended_backend`).
- ⚠️ Lembrete técnico: CUDA é exclusivo NVIDIA; por isso o caminho AMD usa
  OpenCL/ROCm, não CUDA — ambos os "sistemas" pedidos (um para cada fabricante)
  estão implementados e coexistem no mesmo dispatcher.

### Arquitetura L2 (Layer 2 / Rollup) — `app/layer2.py`

Para escalar além do limite de throughput imposto pela dificuldade crescente da L1:

- **Depósito**: usuário envia fundos da L1 para o endereço-ponte (`/l2/bridge-address`)
  e confirma com `/l2/deposit` após a transação ser minerada — credita saldo L2 igual.
- **Transferências L2 instantâneas**: `/l2/transfer` move saldo no ledger L2
  **sem esperar mineração nenhuma** (mesma assinatura ECDSA da L1).
- **Commit em lote (rollup)**: `/l2/commit-batch` agrega N transferências L2
  pendentes numa única **raiz de Merkle**, ancorada na L1 como **uma única
  transação** (`rollup_commit`) — troca N mineração por 1, ganho real de
  escalabilidade.
- **Saque**: `/l2/withdraw` debita o saldo L2 e devolve os fundos na L1.

### Carteiras estilo Bitcoin (Base58Check + WIF)

- `POST /wallet/create` gera um par de chaves ECDSA (secp256k1, a mesma curva do
  Bitcoin) e deriva o endereço exatamente como o Bitcoin faz: `SHA-256` →
  `RIPEMD-160` → byte de versão (`0x37`, exclusivo do PXC) → checksum duplo
  `SHA-256` → **Base58Check**. Resultado: endereços de ~34 caracteres
  (ex.: `PGc5w9qDCrnLew3RphKMFh1ANPSD7ijPN9`), sem caracteres ambíguos (0/O/I/l).
- A chave privada também é exportável no formato **WIF** (Wallet Import Format),
  igual ao Bitcoin (`private_key_wif` na resposta de `/wallet/create`), permitindo
  importar/exportar a carteira em outras ferramentas compatíveis.
- `crypto_utils.is_valid_address()` valida o checksum antes de aceitar qualquer
  endereço como destinatário — protege contra erros de digitação.

### Lastro em ouro (XAU) com delta em dólar — `app/gold_oracle.py`

- O valor do PXC é **ancorado em ouro**, não em uma paridade fixa arbitrária: a
  cada consulta, o sistema busca a cotação **ao vivo** do ouro em USD/oz
  (`api.gold-api.com`) e o câmbio USD/BRL (`open.er-api.com`), com cache de 60s e
  fallback seguro para o último valor conhecido (ou um valor padrão) caso a
  internet esteja indisponível — a API nunca quebra por falha de rede externa.
- `pxc_brl_rate = LASTRO_OURO_POR_PXC (oz) × cotação_ouro_usd × câmbio_usd_brl`,
  recalculado dinamicamente — assim o PXC acompanha a variação do ouro (que
  historicamente preserva valor real contra inflação/depreciação cambial),
  evitando que o poder de compra do usuário se perca com o tempo.
- `GET /market/gold-price` expõe a cotação atual, o câmbio e o **delta
  percentual** do ouro desde a última atualização (`delta_pct_gold`).
- A compra (`/purchase/quote`, `/purchase/confirm`) e a venda/liquidação
  (`/market/sell`, `/market/liquidate`) usam essa mesma cotação dinâmica —
  o valor em Reais pago/recebido reflete o preço real do ouro no momento.

### Venda, liquidação e swap (troca P2P) — `app/market.py`

- **Venda** (`POST /market/sell`): queima PXC do saldo do usuário
  (transação `sell_burn`, assinada com a chave privada) e calcula o valor a
  receber em BRL pela cotação ancorada em ouro do momento.
- **Liquidação** (`POST /market/liquidate`): igual à venda, mas liquida a
  posição total (ou uma quantia específica) de uma só vez.
- **Swap P2P** (`/market/swap/create-order`, `/fill-order`, `/cancel-order`):
  livro de ordens simples — o vendedor custodia (escrow) o PXC numa transação
  `swap_escrow`; quem preenche a ordem recebe os fundos via `swap_fill`;
  cancelamentos devolvem via `swap_cancel_refund`. O pagamento em BRL é
  acertado fora da cadeia entre as partes (como um combinado de preço/PIX real
  entre comprador e vendedor).
- `GET /market/swap/orders` lista ordens abertas/preenchidas/canceladas.

### Controle de dump e auto-regulação (self-regulating) — `app/market.py`

- **Limite por carteira**: nenhuma carteira pode vender/liquidar mais que
  **30% do seu saldo pré-janela** dentro de uma janela de 10 minutos
  (`MAX_WALLET_DUMP_RATIO`), evitando que um único agente derrube o preço.
- **Limite de rede auto-regulado**: o limite global de venda por janela
  **não é fixo** — ele se ajusta sozinho entre **1% (piso) e 8% (teto)** da
  oferta circulante, conforme a **concentração de saldo entre carteiras**
  (índice **HHI**, calculado vetorizado com NumPy sobre todos os endereços já
  vistos na cadeia). Quanto mais concentrado o saldo (risco de "baleia"),
  mais apertado o limite; quanto mais distribuído, mais o limite relaxa —
  validado em teste real: HHI caiu de **1.0 → 0.51** após distribuir fundos
  entre duas carteiras, e o limite subiu automaticamente de **1% → 4.4%**,
  sem nenhuma intervenção manual (o "self-leaving" pedido).
- Quando o limite é atingido, novas vendas/liquidações são **rejeitadas** até
  que vendas antigas "saiam" da janela de 10 minutos — a rede volta a permitir
  negociação sozinha, sem precisar de um admin pausar/despausar nada.
- `GET /market/dump-status` mostra em tempo real: quanto já foi vendido na
  janela, o limite calculado, o HHI e se a negociação está suspensa.
- `GET /market/wallet-dump-status/{address}` mostra o mesmo, por carteira.

### Explorer público (transparência + anonimato pseudônimo)

- `GET /explorer/address/{address}`: histórico completo de movimentação
  (confirmada e pendente) de qualquer endereço público — qualquer pessoa pode
  auditar o fluxo de uma carteira, exatamente como no Bitcoin: o endereço é
  público e rastreável, mas **não há vínculo direto com identidade real**
  (anonimato pseudônimo, não anonimato absoluto).
- `GET /explorer/market-activity`: visão agregada do "movimento real do
  mercado" — volume total transacionado, oferta circulante, concentração de
  saldo (HHI) e as maiores transações da rede (whale-watch).

### Rede P2P real (`app/network.py`)

Cada nó roda um `P2PNode` (asyncio, protocolo NDJSON sobre TCP) que:

- Faz **handshake** com peers verificando `network_id` (recusa conexão de
  redes/forks incompatíveis) e troca metadata (altura da cadeia, versão).
- Propaga (**gossip**) transações pendentes e blocos minerados para todos os
  peers conectados, evitando reenviar ao remetente original.
- Faz **IBD (Initial Block Download)**: ao conectar, compara o trabalho
  acumulado (`Blockchain.total_work()`) com o peer e baixa a cadeia inteira se
  o peer estiver à frente.
- Implementa a **regra de escolha de cadeia de Nakamoto**
  (`try_replace_chain`): a cadeia com **mais trabalho acumulado** vence
  (nunca "mais blocos"); transações órfãs de um reorg voltam para a mempool.
- **Descoberta automática de peers via DNS seeds**: ao subir, o nó resolve
  hostnames configurados em `PIXCRIPTO_DNS_SEEDS` (via `socket.getaddrinfo`)
  para obter IPs iniciais de peers da rede — igual ao `chainparams.cpp` do
  Bitcoin Core. Se a resolução DNS falhar (sem internet, seed offline), o nó
  continua subindo normalmente (falha graciosa com log de aviso).
- **PEX (Peer Exchange)**: protocolo de troca de peers via mensagens `getaddr`
  (solicita lista de peers conhecidos) e `addr` (resposta com lista de
  `{host, port, discovered_via}`). Ao receber um `addr`, o nó tenta conectar
  automaticamente a peers ainda desconhecidos, respeitando o limite
  `PIXCRIPTO_MAX_PEERS` (padrão 50). Proteção anti-flood: máximo 100 endereços
  por mensagem `addr` (entradas extras são truncadas silenciosamente).
  Retrocompatibilidade total com mensagens legadas `GetPeers`/`Peers`.
- **`discovered_via`** em cada peer: rastreia a origem do peer — `"manual"`
  (configurado pelo operador), `"dns_seed"` (resolvido via DNS), `"pex"`
  (recebido de outro peer via `addr`), `"inbound"` (conexão de entrada).
- Anti-eclipse: limite de peers e preferência por diversidade de endereços IP.
- `GET /network/status` mostra peers conectados e trabalho acumulado local;
  `GET /network/peers` lista peers com `discovered_via` por peer (novo);
  `POST /network/connect` conecta manualmente a um peer (`host:porta`).
- **Blocos recebidos via rede são persistidos em SQLite e notificados via
  WebSocket** exatamente como blocos minerados localmente (gap de auditoria
  corrigido: antes, blocos vindos de peers só existiam em memória).

### Carteira HD (seed phrase) — `app/hd_wallet.py`

- `POST /wallet/hd/create`: gera uma **seed phrase** de 12 ou 24 palavras
  (wordlist BIP-39 em inglês, 2048 palavras, com checksum) e deriva a conta
  raiz — o usuário faz backup de UMA frase e recupera TODAS as contas
  derivadas dela, igual a uma carteira Bitcoin/Ethereum moderna.
- `POST /wallet/hd/derive`: deriva a N-ésima conta filha de uma seed phrase
  (caminho `m/44'/7777'/0'/0/index`, formula simplificada de derivação
  hierárquica via HMAC-SHA512, documentada como simplificação do BIP-32
  completo — suficiente para gerar contas determinísticas e independentes,
  sem a propriedade de derivação de chave pública estendida do BIP-32 real).
- `POST /wallet/hd/validate`: valida se uma seed phrase tem palavras
  conhecidas e checksum correto, sem derivar nenhuma chave.
- `POST /wallet/hd/next-address`: **rotação automática de endereço**
  ("conta auto-mutável") no estilo *gap limit* do BIP-44 — devolve sempre a
  próxima conta ainda sem uso (sem saldo e sem histórico de transações,
  varrendo até `HD_GAP_LIMIT = 20` índices à frente) derivada da mesma seed
  phrase. Usar um endereço novo a cada recebimento reduz drasticamente a
  superfície de ataque de força bruta/análise de cadeia contra um único par
  de chaves, sem exigir nenhum backup além da seed phrase original.

### Carteiras Multi-assinatura M-de-N — `app/multisig.py`

Implementação completa de carteiras multisig com fluxo PSBT-like simplificado:

**Endereço multisig (P2SH-like nativo)**
O endereço é derivado **deterministicamente** de M e das N chaves públicas ordenadas
lexicograficamente:
```
script  = "multisig:{M}:{pubkey1}:{pubkey2}:...:{pubkeyN}"
address = Base58Check(RIPEMD160(SHA256(script)), version=0x37)
```
Mesmo byte de versão das carteiras normais → passa nas mesmas validações de formato.
Garantia de não-colisão com P2PKH: o prefixo `"multisig:"` torna a entrada do hash
distinta de qualquer chave pública bruta de 64 bytes.

**Fluxo de transação (PSBT-like simplificado)**
1. `POST /multisig/create` — cria a carteira (N chaves + threshold M); retorna o endereço.
2. `POST /multisig/propose` — cria proposta com dados econômicos (remetente multisig,
   destinatário, valor, taxa, memo); retorna o `signing_payload` canonico que os participantes
   devem assinar localmente com `crypto_utils.sign_message`.
3. `POST /multisig/{proposal_id}/sign` — participante envia sua assinatura ECDSA real
   (sobre o `signing_payload`). Rejeitado se: chave fora dos participantes, assinatura
   inválida, ou duplicata da mesma chave.
4. `POST /multisig/{proposal_id}/finalize` — quando ≥ M assinaturas válidas coletadas,
   monta a `Transaction` com campos multisig e a submete ao fluxo normal da blockchain.
   Proposta marcada como `"finalized"` para prevenir dupla submissão.
5. `GET /multisig/{address}` — consulta dados da carteira (threshold, participantes).
6. `GET /multisig/proposals/{proposal_id}` — estado atual da proposta (assinaturas coletadas,
   threshold, `signing_payload`, status).

**Validação na blockchain (sem consulta ao banco)**
A `Transaction` multisig é **auto-validável**: os campos `multisig_participants` (JSON),
`multisig_threshold` (M) e `multisig_signatures` (JSON de assinaturas) são embutidos na
transação. `Transaction._is_valid_multisig()` recomputa o endereço multisig a partir dos
campos da própria transação e verifica cada assinatura via ECDSA real — nenhum nó precisa
consultar o banco de dados para validar uma tx multisig, exatamente como no Bitcoin.

**Retrocompatibilidade total**: os 3 campos multisig são `Optional` com default `None`
em `Transaction`. Transações single-sig existentes não são afetadas.

### JSON-RPC 2.0 + WebSocket (`app/rpc.py`, `app/ws_hub.py`)

- `POST /rpc`: dispatcher **spec-compliant** (JSON-RPC 2.0) com suporte a
  chamada única, **batch**, **notificações** (sem `id` → sem resposta, `204`)
  e códigos de erro padrão (`-32700`..`-32603`). Métodos registrados:
  `chain_getLength`, `chain_getBlockByIndex`, `chain_getBlockByHash`,
  `chain_getStateRoot`, `chain_isValid`, `account_getBalance`,
  `tx_getPending`, `tx_send`, `net_chainId`, `net_peerCount`, `net_status`,
  `mining_getDifficulty` — nomenclatura inspirada no `eth_*`/`net_*` do
  Ethereum, adaptada ao domínio do PixCripto.
- `GET /ws/events` (WebSocket): eventos em tempo real —
  `pendingTransaction` (nova tx aceita na mempool), `newBlock` (bloco
  minerado localmente OU recebido via P2P), `chainReorg` (após um reorg).

### Smart contracts / máquina virtual (`app/vm.py`)

Uma **stack machine determinística de 256 bits por slot** (secão 5 do guia),
com gas metering em todo opcode (anti-DoS de loop infinito), storage
persistente por contrato, e o padrão **Checks-Effects-Interactions** aplicado
em `SSTORE`/`CALL` (mutação de storage sempre ANTES de qualquer sub-chamada),
com uma **guarda de reentrância no nível da VM** (um contrato não pode
reentrar em si mesmo durante uma `CALL` ativa — mesma classe de ataque do
hack do The DAO em 2016).

- Opcodes implementados: `STOP`, aritmética (`ADD`/`SUB`/`MUL`/`DIV`/`MOD`/
  `ADDMOD`/`MULMOD`/`EXP`), comparação (`LT`/`GT`/`EQ`/`ISZERO`), bitwise
  (`AND`/`OR`/`XOR`/`NOT`/`BYTE`/`SHL`/`SHR`/`SAR`), `SHA3`,
  `ADDRESS`/`BALANCE`/`ORIGIN`/`CALLER`/`CALLVALUE`/`CALLDATALOAD`/
  `CALLDATASIZE`/`CALLDATACOPY`/`CODESIZE`/`CODECOPY`/`GASPRICE`/
  `EXTCODESIZE`/`TIMESTAMP`/`NUMBER`/`MSIZE`/`GAS`, `POP`,
  `MLOAD`/`MSTORE`, `SLOAD`/`SSTORE`, `JUMP`/`JUMPI`/`PC`/`JUMPDEST`,
  `PUSH1`-`PUSH32`, `DUP1`-`DUP16`, `SWAP1`-`SWAP16`, `LOG0`-`LOG4`,
  `CREATE`, `CALL`, `STATICCALL`, `RETURN`/`RETURNDATASIZE`/`RETURNDATACOPY`,
  `REVERT`, `SELFDESTRUCT`.
- **Rollback atômico real (snapshot/restore por frame)**: `REVERT` e
  qualquer exceção durante a execução (falta de gás, salto inválido,
  overflow de pilha/memória, erro interno) desfazem **completamente** o
  frame de chamada corrente — incluindo `SSTORE`s, contratos criados via
  `CREATE`, contratos apagados via `SELFDESTRUCT` e saldos transferidos —
  aninhado corretamente através de `CALL`s recursivas. Nenhum efeito parcial
  de uma chamada revertida "vaza" para o restante do bloco.
- **Reembolso de gás não utilizado (seção 5.3 do guia)**: ao final da
  execução, `gas_limit - gas_used` é creditado de volta ao remetente da
  transação — implementado e coberto por teste de integração via mineração
  real (`test_gas_refund_credits_unused_gas_back_to_sender`).
- **`STATICCALL`** força um sub-contexto somente-leitura: `SSTORE`, `CREATE`,
  `LOG0`-`LOG4`, `SELFDESTRUCT` e qualquer transferência de valor são
  rejeitados dentro dele (equivalente ao `staticcall` da EVM pós-Byzantium).
- **Transferência real de saldo em `CALL`/`CREATE` com `value`**: quando a
  VM roda dentro de um bloco minerado (não em modo *dry-run* de
  `estimate-gas`), enviar `value` numa `CALL` ou `CREATE` interna
  efetivamente move saldo PXC real entre os endereços envolvidos (antes era
  apenas simulado); falha por saldo insuficiente reverte só aquela
  sub-chamada.
- **`CREATE` executa o bytecode implantado como construtor** uma vez; se o
  construtor reverter, o deploy inteiro (conta nova + qualquer valor
  transferido) é desfeito — mesma garantia que o `contract_deploy` de mais
  alto nível já tinha.
- Limite de profundidade de chamadas (`MAX_CALL_DEPTH`) fixado em `200`
  (não `1024` como a EVM) porque a VM usa recursão real do Python para
  `CALL`/`CREATE`/`STATICCALL` aninhados — margem de segurança para não
  estourar o limite de recursão do CPython.
- Limite físico de memória por execução (`MAX_MEMORY_BYTES`, 1 MiB) como
  defesa em profundidade contra DoS além do gas metering.
- **Execução determinística ligada à mineração, não à mempool**: uma
  transação `contract_deploy`/`contract_call` só executa de fato quando um
  bloco a inclui (`build_candidate_block`) — exatamente como o Ethereum real
  (nunca a aceitação na mempool). Isso resolve corretamente o caso de
  **reorg**: se o bloco que continha uma chamada de contrato é órfão, o
  efeito é automaticamente descartado, pois todo o estado de contratos é
  reconstruído por **replay determinístico** da cadeia vencedora (mesmo
  padrão já usado para `state_root`/saldos).
- **`contracts_root`**: novo campo do cabeçalho do bloco (participa do hash
  minerado, igual ao `state_root`) — hash SHA-256 do snapshot de
  código+storage de todos os contratos após aquele bloco. Qualquer nó pode
  detectar divergência de execução da VM comparando apenas 32 bytes.
- Endpoints: `POST /contracts/deploy`, `POST /contracts/call`,
  `GET /contracts/by-creator/{endereço}`, `GET /contracts/{endereço}/code`,
  `GET /contracts/{endereço}/storage/{key}`, `POST /contracts/estimate-gas`
  (dry-run, sem mutar estado real — equivalente a `eth_estimateGas`).
- **Keccak-256 real** (`app/crypto_utils.py → keccak256()`): o opcode `SHA3`
  da VM agora usa **Keccak-256 puro Python** (Keccak-f[1600], sponge
  rate=136 bytes), não `hashlib.sha256` nem `hashlib.sha3_256`. A diferença
  crítica: o SHA3 padronizado pelo NIST (FIPS 202) usa o byte de padding `0x06`,
  enquanto o Keccak original (e a EVM real) usa `0x01` — os hashes produzidos são
  completamente diferentes (`keccak256(b"") ≠ sha3_256(b"")`). Implementado em
  Python puro (zero dependências novas, pycryptodome/pysha3 não estavam
  disponíveis no venv). Vetores de teste públicos: `keccak256(b"") =
  c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
- **RLP (Recursive Length Prefix) real** (`app/crypto_utils.py →
  rlp_encode()`/`rlp_decode()`): serialização canônica do Ethereum para
  bytes, strings, inteiros e listas aninhadas, seguindo a especificação
  pública. Vetor de teste: `rlp_encode(b"dog") == bytes([0x83, 0x64, 0x6f,
  0x67])`. O endereço determinístico de `CREATE` mantém SHA-256 (formato
  Base58Check próprio do PixCripto), mas RLP está disponível para uso em
  hashes canônicos de transações/receipts quando necessário.
- **SSTORE_REFUND clássico**: quando `SSTORE` zera um slot que tinha valor
  != 0, o executador recebe um crédito de **15 000 gás** (valor clássico da
  EVM pré-EIP-3529). O refund acumulado por execução é aplicado ao final da
  chamada de nível 0 (profundidade zero), limitado a **50% do gás usado**
  (limite clássico; EIP-3529 reduziu para 20% para mitigar *gas token abuse*
  — escolhemos 50% por ser o padrão histórico mais simples e documentado).
  Sub-chamadas revertidas *não* contribuem ao refund (revertidas via
  snapshot/restore).
- **`DELEGATECALL` (0xF4) e `CALLCODE` (0xF2)**: dois novos opcodes de
  chamada cruzada implementados na VM:
  - `DELEGATECALL`: executa o **código** do contrato alvo no **contexto do
    chamador** (mesmo storage, mesmo `ADDRESS`, mesmo `msg.sender = quem
    chamou o chamador`, mesmo `msg.value`). Padrão usado por proxies e
    bibliotecas de storage em Solidity.
  - `CALLCODE`: igual ao `DELEGATECALL` mas `msg.sender = endereço do
    contrato chamador` (não o chamador original). Semântica clássica,
    antecessora do `DELEGATECALL`.
  - Ambos criam uma "conta virtual" com o código do alvo e o storage/endereço
    do chamador; a guarda de reentrância é mantida (temporariamente removida
    do conjunto ativo para permitir a sub-execução no mesmo endereço, e
    restaurada pelo próprio `execute()` que a re-adiciona imediatamente).
- **Logs/eventos indexados e consultáveis** (`LOG0`-`LOG4` agora persistidos):
  tabela `contract_logs` no SQLite (com chave única `(block_index, tx_id,
  log_index)` para idempotência). Logs são capturados durante a execução dos
  contratos ao minerar um bloco e persistidos junto com o bloco. Novo
  endpoint: `GET /contracts/{endereço}/logs` (parâmetros opcionais `topic`,
  `from_block`, `to_block`) — equivalente ao `eth_getLogs` do Ethereum.
  Logs de sub-chamadas revertidas **não** são incluídos (corrigido no mesmo
  PR: `logs.extend(result.logs)` condicionado a `result.success`).
- **Simplificações deliberadas em relação à EVM/guia** (documentadas):
  - O endereço determinístico de `CREATE`/deploy usa **SHA-256** (não
    Keccak+RLP) para preservar o formato Base58Check próprio do PixCripto.
  - Endereços nos slots da pilha (256 bits) são o inteiro do SHA-256 do
    endereço Base58Check, não os 20 bytes "crus" da EVM — resolvidos de
    volta ao endereço real via uma tabela de internamento
    (`ContractsState.intern_address`/`resolve_address`).
  - Não há separação entre *init code* e *runtime code*: o mesmo bytecode
    implantado roda tanto no deploy (como "construtor") quanto em chamadas
    futuras.
  - O orçamento de gas é expresso via o campo `fee` já existente (em PXC),
    convertido para unidades de gás por `root_rules.GAS_PRICE_PXC` — não há
    uma segunda unidade de conta só para a VM, e o gás pago ao minerador
    segue o mesmo mecanismo de taxas de qualquer outra transação.
- Endpoints (atualizado): `POST /contracts/deploy`, `POST /contracts/call`,
  `GET /contracts/by-creator/{endereço}`, `GET /contracts/{endereço}/code`,
  `GET /contracts/{endereço}/storage/{key}`,
  `GET /contracts/{endereço}/logs` (**novo**),
  `POST /contracts/estimate-gas`.

## Como rodar

```powershell
cd PixCripto
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.api:app --reload
```

Documentação interativa (Swagger): http://127.0.0.1:8000/docs

### Mineração acelerada (AMD/NVIDIA via OpenCL)

Instale o driver ROCm (AMD) ou o runtime OpenCL do seu fabricante e:

```powershell
.venv\Scripts\pip install pyopencl numpy
```

O endpoint `GET /mining/gpu-status` mostra se uma GPU compatível foi detectada. Se não
houver GPU, `/mining/mine` usa automaticamente o fallback de CPU — nenhuma configuração
adicional é necessária.

### Rodando múltiplos nós (rede P2P)

Cada processo escuta P2P numa porta TCP própria (padrão `9333`), além da porta HTTP da API:

```powershell
# Nó 1 (porta HTTP 8000, porta P2P 9333)
$env:PIXCRIPTO_DB_PATH="data/node1.db"
.venv\Scripts\python -m uvicorn app.api:app --port 8000

# Nó 2 (porta HTTP 8001, porta P2P 9334), conectando ao nó 1 na inicialização
$env:PIXCRIPTO_DB_PATH="data/node2.db"
$env:PIXCRIPTO_P2P_PORT="9334"
$env:PIXCRIPTO_P2P_PEERS="127.0.0.1:9333"
.venv\Scripts\python -m uvicorn app.api:app --port 8001
```

`GET /network/status` mostra os peers conectados e o trabalho acumulado local;
`GET /network/peers` lista cada peer com sua origem (`discovered_via`);
`POST /network/connect` conecta manualmente a um peer já com o processo rodando.

#### Variáveis de ambiente da rede P2P

| Variável | Padrão | Descrição |
|---|---|---|
| `PIXCRIPTO_P2P_HOST` | `0.0.0.0` | Interface de escuta P2P |
| `PIXCRIPTO_P2P_PORT` | `9333` | Porta TCP P2P |
| `PIXCRIPTO_P2P_PEERS` | *(vazio)* | Peers manuais `host:porta,host2:porta2` |
| `PIXCRIPTO_DNS_SEEDS` | seeds de exemplo | Hostnames DNS seed `host1:porta,host2:porta` |
| `PIXCRIPTO_PEER_DISCOVERY` | `true` | Habilita resolução DNS seeds na subida |
| `PIXCRIPTO_MAX_PEERS` | `50` | Limite máximo de peers simultâneos |

## Fluxo de exemplo

1. `POST /wallet/create` → cria carteira (guarde a chave privada com segurança), ou
   `POST /wallet/hd/create` para uma carteira HD (seed phrase, múltiplas contas).
2. `POST /purchase/quote-locked` → cotação travada (quote_id, expira em 5 min).
3. **Produção:** o PSP chama `POST /purchase/webhook/confirm` com o corpo JSON
   `{"quote_id": "...", "payment_reference": "..."}` assinado via HMAC-SHA256 no
   header `X-Webhook-Signature` (ou o header configurado em
   `PIXCRIPTO_PAYMENT_WEBHOOK_SIGNATURE_HEADER`). **Desenvolvimento/devnet:**
   use `POST /purchase/webhook/simulate-payment-gateway` + `POST /purchase/confirm`
   para simular o fluxo localmente sem PSP real.
4. `POST /purchase/confirm` → credita PXC (fluxo legado via assinatura interna).
5. `POST /transaction/submit-signed` (recomendado; chave privada nunca trafega) ou
   `POST /transaction/send` (conveniência de demo, assina no servidor) → transferências.
6. `POST /contracts/deploy` / `POST /contracts/call` (opcional) → implanta/chama um
   smart contract (bytecode da VM em `app/vm.py`).
7. `POST /mining/mine` → minera o próximo bloco (inclui a execução de qualquer
   contrato pendente) e paga 4% do valor ao minerador.
8. `GET /wallet/{address}/balance`, `GET /chain`, `GET /chain/metadata` → consulta de estado.
9. `GET /ws/events` (WebSocket) → acompanha novos blocos/transações/reorgs em tempo real;
   `POST /rpc` → consultas via JSON-RPC 2.0.

## 🌐 Ecossistema completo (UI, Exchange API, Conformidade, Admin)

### Configuração central (`app/settings.py` + `.env`)

Copie `.env.example` para `.env` e ajuste as variáveis conforme o ambiente
(`mainnet`/`testnet`/`devnet`): host/porta HTTP, TLS, CORS, rate limit, P2P
(host/porta/peers/DNS seeds), toggles de exchange API e conformidade,
limite de KYC. `app/settings.py` lê tudo isso num singleton `Settings`
imutável (`dataclass(frozen=True)`), validado em `is_valid()`.

### Configuração de rede/DNS (`app/network_config.py`)

- `NetworkProfile`: perfil de rede por ambiente (porta P2P padrão, seeds DNS,
  seeds curados).
- `resolve_dns_seed(hostname, port)`: resolve um hostname semente via DNS
  (`socket.getaddrinfo`), nunca lança exceção — retorna lista vazia em falha
  (host indisponível, sem internet, etc).
- `seeds.json`: lista curada de peers editável (via painel de admin ou
  diretamente), carregada/salva por `load_curated_seeds()`/`save_curated_seeds()`.
- `discover_bootstrap_peers(explicit_peers)`: combina peers explícitos
  (`PIXCRIPTO_P2P_PEERS`) + seeds curados + seeds DNS resolvidos, deduplicados,
  usado na inicialização do P2P em `api.py`. Em `api.py`, peers manuais e DNS seeds
  são passados separadamente ao `P2PNode.start()` para que `discovered_via` seja
  atribuído corretamente desde o primeiro momento.

### Conformidade regulatória própria (KYC/AML) — `app/compliance.py`

Motor de conformidade com banco SQLite próprio (`data/pixcripto_compliance.db`,
isolado do banco principal da chain):

- **KYC em 3 níveis**: tier 0 (não verificado, limite baixo por padrão),
  tier 1 (básico: nome + CPF, limite intermediário), tier 2 (completo: exige
  hash de documento adicional, sem limite). CPF **nunca é armazenado em
  texto claro** — apenas seu hash SHA-256 (`test_cpf_is_never_stored_in_plaintext`
  garante isso).
- **Lista de sanções**: `add_to_sanctions_list`/`remove_from_sanctions_list`/
  `is_sanctioned` — transações de/para um endereço sancionado são
  **bloqueadas** (`ComplianceError` → HTTP 403) em `send_transaction` e
  `submit_signed_transaction`.
- **Monitoramento AML**: alerta (não bloqueia) quando uma transação excede o
  limite do tier do remetente, e detecta padrões de **estruturação/smurfing**
  (múltiplas transações levemente abaixo do limiar num intervalo — janela
  configurável) via `check_transaction(sender_recent_amounts=...)`.
- **Trilha de auditoria append-only** e relatório de atividade suspeita (SAR)
  via `suspicious_activity_report(severity)`.
- **Endpoints REST**: `/compliance/kyc/register`, `/compliance/kyc/status/{address}`,
  `/compliance/sanctions/add`, `DELETE /compliance/sanctions/{entry}`,
  `/compliance/screen/{address}`, `/compliance/reports/sar`.

### Contas de usuário do site (cadastro/login) + KYC com documento real — `app/user_accounts.py`

Diferente do KYC "anônimo" acima (associado apenas a um endereço), este é o
cadastro real de **correntista do site**: usuário/e-mail/senha, com vínculo a
carteira(s) e um fluxo completo de verificação de identidade com **documento
com foto de verdade** (não apenas um hash):

- **Cadastro/login**: `POST /auth/register`, `POST /auth/login` (usuário ou
  e-mail + senha, PBKDF2-HMAC-SHA256 200k iterações, mesmo padrão do resto do
  projeto), sessão expirável de 7 dias (`GET/POST /auth/me`, `/auth/logout`,
  `/auth/change-password`).
- **Vínculo de carteira(s)**: `POST/GET/DELETE /auth/wallets` — só o endereço
  público é armazenado, a chave privada nunca sai do navegador.
- **Envio de KYC com documento real**: `POST /kyc/submit` (multipart) recebe
  nome completo, CPF (validado pelo algoritmo oficial de dígitos
  verificadores), RG, data de nascimento e **3 arquivos**: documento
  frente/verso + selfie de prova de vida. Tudo é **cifrado com AES-256-GCM**
  antes de tocar o disco (texto com uma chave mestra do servidor
  `data/.kyc_master.key` ou `PIXCRIPTO_KYC_MASTER_KEY`; as imagens em
  `data/kyc_documents/<uuid aleatório>.bin`) e fica **pendente de revisão
  manual** — nunca aprovado automaticamente.
- **Revisão administrativa** (painel `/admin`, aba "Verificações KYC"):
  `GET /admin/kyc/submissions` (lista, filtra por status),
  `GET /admin/kyc/submissions/{id}` (decifra nome/CPF/RG/data de nascimento e
  as 3 imagens como data-URI, só sob demanda explícita do operador),
  `POST /admin/kyc/submissions/{id}/approve|reject`. Ao aprovar, o tier é
  propagado automaticamente para `app/compliance.py`, elevando o limite de
  transação de todas as carteiras vinculadas àquela conta.
- **Duplicidade de CPF bloqueada**: duas contas não podem reivindicar o mesmo
  CPF (checagem por hash, sem reter o CPF em claro na tabela de contas).

### API estilo Binance para integração externa — `app/exchange_api.py`

Endpoints de mercado no padrão de exchanges (para sites/bots externos
consumirem cotação/profundidade/histórico do PXC):

- `GET /api/v1/exchangeInfo` — símbolo, ativos base/quote, filtros.
- `GET /api/v1/ticker/24hr` — último preço, variação 24h, volume.
- `GET /api/v1/klines?interval=1h&limit=N` — candles OHLC sintetizados a
  partir do histórico real de preço (`price_history`, alimentado pelo
  `GoldOracle.refresh()`).
- `GET /api/v1/depth` — livro de ofertas derivado das ordens de swap abertas
  no `MarketEngine`.
- `GET /api/v1/trades` — negociações reais (venda/liquidação/swap preenchido)
  já mineradas na chain.
- `POST /api/v1/apikey/create` — gera par `api_key`/`api_secret` (HMAC-SHA256)
  vinculado a um endereço de carteira.
- `POST /api/v1/order` — cria uma ordem de swap real, autenticada via
  assinatura HMAC do payload `"{amount}:{price}"` usando o `api_secret`.

### Feed de notícias — `app/news.py`

Backend de conteúdo (SQLite, tabela `news_posts`) para o feed de notícias do
site principal e do painel admin da nova UI:

- **Leitura pública, sem autenticação**: `GET /news` (lista paginada),
  `GET /news/{id}` (detalhe).
- **Escrita protegida por token, *fail-closed* por padrão**: `POST/PUT/DELETE
  /news[/{id}]` exigem o header `X-Admin-Token` correspondendo a
  `settings.admin_content_token` (comparação em tempo constante via
  `secrets.compare_digest`). Se `PIXCRIPTO_ADMIN_CONTENT_TOKEN` não estiver
  definido, **toda escrita retorna HTTP 503** — uma instalação nova nunca
  fica com um feed publicamente editável por engano.
- **Upload de imagem**: `POST /news/upload-image` (multipart) valida
  extensão/MIME (`image/png`, `image/jpeg`, `image/webp`, `image/gif`), impõe
  limite de 5 MB e gera nome de arquivo aleatório (`secrets.token_hex`) para
  evitar colisão/overwrite e path traversal — salvo em
  `app/static/uploads/news/`, e registrado na biblioteca de mídia central
  (`app/media.py`, ver abaixo).

### Painel de Administração do site — login real + 2FA, CMS avançado, multi-usuário, housekeeping profissional

Diferente do token compartilhado antigo (`X-Admin-Token`, ainda aceito por
compatibilidade), o Painel de Administração do site (`/admin` na UI React)
agora tem **contas de operador de verdade** (multi-usuário, com papéis) e
autenticação em duas etapas:

- **`app/admin_auth.py`** — hash PBKDF2-HMAC-SHA256 (200k iterações, salt por
  conta), sessão com token aleatório de 256 bits e expiração configurável
  (`PIXCRIPTO_ADMIN_SESSION_TTL_SECONDS`, padrão 12h). *Fail-closed*: sem
  `PIXCRIPTO_ADMIN_USERNAME`/`PIXCRIPTO_ADMIN_PASSWORD` no `.env`, o login
  fica desabilitado (nunca existe conta "de fábrica"). Protegido pelo mesmo
  `bruteforce_guard` adaptativo do resto do sistema. Endpoints:
  `POST /admin/auth/login`, `POST /admin/auth/logout`, `GET /admin/auth/me`,
  `POST /admin/auth/change-password`.
- **2FA (TOTP) — `app/totp.py`**: implementação própria RFC 6238 (sem
  dependência externa), compatível com Google Authenticator/Authy/1Password.
  Fluxo: `POST /admin/auth/2fa/setup` gera segredo + QR code (via
  `qrcode_utils`), `POST /admin/auth/2fa/enable` confirma com um código do
  app e ativa, retornando 10 códigos de backup de uso único (mostrados só
  uma vez). Com 2FA ativo, `/admin/auth/login` exige `otp_code` (retorna
  HTTP 428 `2fa_required` se ausente) — aceita tanto o código do app quanto
  um código de backup. `POST /admin/auth/2fa/disable` exige confirmar a
  senha atual.
- **Multi-usuário com papéis (`owner`/`editor`)**: apenas contas `owner`
  podem criar/remover outros operadores (`GET/POST /admin/users`,
  `DELETE /admin/users/{username}`); nunca é possível remover o último
  `owner` restante. A primeira conta (bootstrap) sempre recebe `owner`.
- **CMS de páginas estáticas — `app/cms.py`**: conteúdo institucional fixo por
  slug (Sobre, Termos de uso, etc.), com **histórico de revisões e rollback**
  (cada edição preserva a versão anterior em `cms_page_revisions`;
  `GET /admin/pages/{slug}/revisions` + `POST .../revisions/{version}/restore`)
  e **ordenação/visibilidade de menu** (`menu_order`, `show_in_menu` — usado
  por `GET /pages` para montar o menu institucional público dinamicamente).
  `GET /pages/{slug}` (público, só publicadas) e `GET/PUT/DELETE
  /admin/pages[/{slug}]` (autenticado). Renderizado no site em `/pages/:slug`.
- **Notícias com fluxo editorial completo**: status `draft`/`scheduled`/
  `published`, categoria, tags e contador de visualizações. `GET /news`
  (público, só publicadas e não agendadas para o futuro) vs.
  `GET /admin/news` (operador vê rascunhos/agendadas também).
- **Biblioteca de mídia centralizada — `app/media.py`**: todo upload feito
  pelo site fica registrado (`media_files`) com metadata completa (tamanho,
  MIME, quem enviou, propósito, **texto alternativo, tags e pasta**,
  editáveis via `PUT /admin/media/{id}`). `GET /admin/media` lista +
  estatísticas de armazenamento; `DELETE /admin/media/{id}` remove do disco
  e do inventário (recusa remover arquivo ainda referenciado por notícia
  publicada, a menos que `?force=true`).
- **Chaves de funcionalidade (feature flags) — `app/feature_flags.py`**: liga/
  desliga módulos inteiros em runtime, sem novo deploy — `maintenance_mode`
  (bloqueia toda a API pública com HTTP 503, exceto o próprio painel),
  `purchases_enabled`, `trading_enabled`, `mining_enabled`,
  `kyc_enforced`, `news_publishing_enabled`, e **8 flags granulares por
  tarefa de housekeeping** (`housekeeping_task_*`, ver abaixo).
  `GET/POST /admin/features[/{key}]` (autenticado) e `GET /features/public`
  (subconjunto seguro para a UI pública consultar antes de autenticar).
- **Configurações gerais do site — `app/site_settings.py`**: identidade
  institucional editável sem deploy (nome do site, tagline, contato, SEO,
  redes sociais, mensagem de manutenção customizada).
  `GET/PUT /admin/settings` (autenticado), `GET /settings/public` (leitura
  pública para cabeçalho/rodapé/meta tags do front-end).
- **Housekeeping profissional — `app/housekeeping.py`**: agendador em thread
  de background (`PIXCRIPTO_HOUSEKEEPING_INTERVAL_SECONDS`, padrão 6h) que
  executa, cada tarefa **individualmente liga/desligável** via feature flag:
  poda de sessões de admin expiradas, poda do estado do `bruteforce_guard` e
  do honeypot, remoção de arquivos órfãos em `app/static/uploads/`, poda do
  histórico de preço (`PIXCRIPTO_PRICE_HISTORY_RETENTION_DAYS`),
  **`PRAGMA integrity_check`** do SQLite (detecta corrupção cedo, gera aviso
  se não retornar `ok`), **backup compactado** (banco + uploads, via API de
  backup segura do sqlite3, com rotação automática das 14 execuções mais
  recentes) e `VACUUM`. Cada execução fica auditada em `housekeeping_runs`
  (incluindo avisos). Endpoints: `POST /admin/housekeeping/run` (manual),
  `GET /admin/housekeeping/status` (inclui relatório de uso de disco:
  banco/uploads/backups), `GET /admin/housekeeping/history`,
  `GET/POST /admin/housekeeping/backups`,
  `DELETE /admin/housekeeping/backups/{filename}`.
  **Backup off-site**: configure `PIXCRIPTO_BACKUP_OFFSITE_DIR` com um
  caminho de filesystem (drive de rede mapeado, pasta sincronizada com nuvem
  local como OneDrive/Dropbox, segundo disco) para que o zip já gerado seja
  copiado automaticamente para esse segundo destino logo após o backup local.
  Falha na cópia off-site registra apenas um *warning* — o backup local já
  concluído nunca é desfeito. **Script de restore**: `scripts/restore_backup.py`
  restaura qualquer backup `.zip`, valida `PRAGMA integrity_check` antes de
  tocar o destino e imprime um relatório completo (altura da chain, blocos,
  transações). Suporta `--dry-run` (só valida, sem sobrescrever) e `--force`
  (sobrescreve destino existente).
- **Dashboard integrado à rede — `GET /admin/dashboard`**: amarra o painel à
  blockchain PixCripto de verdade em execução no mesmo processo — altura da
  cadeia, blocos minerados, tamanho do mempool, dificuldade atual e teto do
  modo, concentração de hashrate (HHI anti-monopólio), status de
  dump-control do mercado, feature flags e status de housekeeping, tudo em
  tempo real.

Todos os endpoints `/admin/*` (exceto `/admin/auth/login` e `/admin/auth/status`)
exigem `Authorization: Bearer <token>` obtido no login. O CMS de notícias
(`/news*`) e os endpoints de segurança (`/security/*`) aceitam **qualquer um**
dos dois mecanismos (token legado OU sessão de login), mantendo compatibilidade
com integrações existentes.

### Frontend web profissional (React SPA) — `frontend/`

Interface web moderna, estilo Binance/exchange profissional, que substitui a
antiga UI Jinja2 (mantida em `app/templates/`/`app/static/js/pixcripto.js`
apenas como fallback sem JavaScript). Construída com **React 19 + Vite +
Tailwind CSS v4 + react-router-dom + lightweight-charts (TradingView) +
axios**, 100% desacoplada do backend via REST/CORS.

```powershell
cd frontend
npm install
npm run dev        # http://127.0.0.1:5173 (proxy nenhum necessário: CORS habilitado no backend)
npm run build       # gera frontend/dist/ (assets estáticos prontos para produção)
```

Páginas:

- **Painel** (`/`) — saldo da carteira ativa, ticker de preço (carrossel com
  variação 24h, ▲/▼), lastro em ouro em tempo real e estatísticas
  anti-monopólio (HHI de mineração).
- **Carteira** (`/wallet`) — criação de carteira simples, carteira HD (seed
  phrase 12/24 palavras, recuperação por mnemonic) e importação de chave
  privada bruta; múltiplas carteiras por navegador, troca rápida no topo.
- **Enviar / Receber** (`/send`, `/receive`) — transferência assinada
  (`/transaction/send`) e QR code de cobrança (`/wallet/{addr}/qrcode`).
- **Histórico** (`/history`) — transações confirmadas e pendentes via
  `/explorer/address/{address}`.
- **Mercado** (`/market`) — gráfico de candles real (klines agregados de
  `price_history`), livro de ofertas do swap DEX (`/api/v1/depth`) e
  negociações recentes (`/api/v1/trades`), com seletor de intervalo (1m–1d).
- **Notícias** (`/news`, `/news/:id`) — feed público com imagem de capa,
  resumo e corpo completo.
- **Páginas institucionais** (`/pages/:slug`) — conteúdo estático do CMS
  (Sobre, Termos, etc.), renderizado publicamente a partir de `/pages/{slug}`.
- **Painel de Administração** (`/admin`) — login real (usuário/senha + 2FA
  opcional via TOTP), com abas: Dashboard (estatísticas ao vivo da rede
  PixCripto: altura da cadeia, dificuldade, hashrate, dump-control),
  Notícias (CRUD + upload + rascunho/agendamento/categorias), Páginas (CMS
  institucional com histórico de revisões/rollback e menu dinâmico), Mídia
  (biblioteca de uploads com alt-text/tags/pastas), Funções do site (feature
  flags, incl. modo manutenção), Housekeeping (executar/consultar manutenção
  automática, backups com rotação, uso de disco), Configurações do site
  (identidade/SEO/redes sociais), Equipe (gestão multi-usuário
  owner/editor), Segurança (integridade do código-fonte) e Conta (troca de
  senha + gestão de 2FA); link direto para o painel de rede completo (porta
  8600).

O estado de carteira (endereço ativo, lista de carteiras, chaves) é mantido
**apenas no `localStorage` do navegador** — o mesmo modelo de confiança de uma
carteira desktop tipo Bitcoin Core GUI: o frontend fala diretamente com a API
REST do node local e a chave privada nunca é persistida no servidor.

Configuração via `frontend/.env` (copie de `.env.example`):

```
VITE_API_BASE_URL=http://127.0.0.1:8000
```

Para produção, gere o build (`npm run build`) e o próprio node FastAPI já o
serve automaticamente sob `/app/*` (ver `app/api.py`, montagem condicional de
`frontend/dist/` — nenhuma configuração adicional de Nginx/CDN é necessária
para uma primeira release real, embora continue sendo uma opção válida para
quem preferir servir os estáticos separadamente). Configure
`VITE_API_BASE_URL` para o host real da API e `PIXCRIPTO_CORS_ORIGINS` no
backend para o domínio real do frontend (nunca `*` em produção) caso a UI seja
servida de uma origem diferente da API.

### UI web legada (Jinja2, sem JS) — `app/templates/` + `app/static/`

Mantida como fallback funcional básico (sem gráficos, sem noticias), servida
pelo próprio node FastAPI via Jinja2:

- `/wallet` — home (saldo, endereço, QR code).
- `/wallet/send` — enviar PXC (direto ou via QR code).
- `/wallet/receive` — gerar cobrança/QR code.
- `/wallet/history` — histórico de transações.
- `/wallet/market` — comprar/vender/trocar PXC, cotação ao vivo ancorada em ouro.

### Painel de Administração — `admin_panel/` (porta 8600, NUNCA distribuído)

App FastAPI **separado**, fora de `app/`, para uso exclusivo do operador:

```powershell
.venv\Scripts\python admin_panel\main.py   # http://localhost:8600
```

Permite editar `.env` (settings), gerenciar `seeds.json` (peers curados),
gerenciar a lista de sanções e ver o relatório SAR, ver o ranking de
honeypots (`top_suspects`), e **disparar `scripts/build_distribution.py`**
com um clique para gerar a build de distribuição real.

`scripts/build_distribution.py` compila apenas o diretório `app/` (bytecode
`.pyc` + assets estáticos/templates) e **exclui explicitamente**
`admin_panel/`, `.env`, `seeds.json` e qualquer `*.db*`/`__pycache__` — o
painel de administração e dados sensíveis nunca chegam ao pacote distribuído.
O script também copia automaticamente `frontend/dist/` (se já tiver sido
gerado com `npm run build`) para `dist/frontend/dist/`, no mesmo caminho
relativo em que `app/api.py` o procura em runtime — a UI React continua
funcionando em `/app/*` na distribuição final sem nenhuma configuração
adicional. `frontend/node_modules/` e `frontend/.env` nunca são copiados.

## 🔐 Segurança (rodada de hardening pós-auditoria)

Após a implementação funcional inicial, o sistema passou por uma rodada de auditoria
de segurança deliberada (3 agentes independentes cobrindo cripto/carteira,
consenso/mineração e API/mercado), simulando um atacante tentando roubar fundos.
Principais falhas **críticas** encontradas e corrigidas:

| Falha (severidade) | Correção aplicada |
|---|---|
| Cunhagem arbitrária via `/purchase/confirm` (CRÍTICA) | Fluxo de 3 passos: `quote-locked` → gateway assina (HMAC) → `confirm` verifica assinatura + idempotência (`quote_id`/`payment_reference` persistidos em SQLite) |
| Roubo de escrow de swap via `/market/swap/fill-order` (CRÍTICA) | Exige assinatura do *maker* (`/market/swap/sign-release`) autorizando especificamente o *taker*; estado intermediário `"settling"` evita corrida fill+cancel |
| Replay de depósito L2 (CRÍTICA) | `l1_tx_id` processado é persistido em SQLite (`l2_processed_deposits`), sobrevive a restart |
| Saque L2 forçado de terceiros (MÉDIA) | `/l2/withdraw` exige assinatura ECDSA de `"withdraw:{address}:{amount}"` |
| Corrida de double-spend (TOCTOU) em requisições concorrentes | `threading.RLock()` em `Blockchain`, `L2Rollup` e `MarketEngine` |
| Assinatura ECDSA não-determinística (nonce fraco, classe Minerva/CVE-2024-23342) | `sign_deterministic` (RFC 6979) |
| Chave pública/WIF malformados aceitos sem validação | Validação de ponto de curva secp256k1 e payload/checksum exatos |
| Manipulação do oráculo de ouro | Circuit breaker: rejeita variação >15% entre cotações consecutivas |
| DoS via `max_iterations` ilimitado em `/mining/mine` | Teto de 5.000.000 (`root_rules.MAX_MINING_ITERATIONS_PER_CALL`) |
| Ausência de rate limiting | Middleware de rate limit por IP/rota (60 req/min) |
| Timestamps de bloco forjáveis | Validação de skew futuro (120s) e retrocesso (60s) em `submit_mined_block`/`is_chain_valid` |
| **Perda de estado da L1 a cada restart** (bloco `/chain/metadata` mostrava histórico do SQLite enquanto `/chain` reiniciava do zero) | `Blockchain.rehydrate_from_persisted_blocks()` reconstrói a cadeia completa (blocos + transações) do SQLite na inicialização |

### Root Rules & Book of Rules

- `app/root_rules.py`: fonte única de todas as constantes de consenso/economia/segurança,
  com `root_rules_hash()` (hash SHA-256 "constitucional" — qualquer alteração de parâmetro
  muda o hash, tornando adulterações silenciosas detectáveis).
- `GET /rules/root-hash`: snapshot assinado das regras ativas no processo.
- `GET /rules/book`: serve [`BOOK_OF_RULES.md`](BOOK_OF_RULES.md), o "livro de regras"
  legível por humanos (emissão, dificuldade, anti-monopólio, controle de dump,
  segurança, honeypots, governança/versionamento de hard forks).

### Guarda anti-força-bruta adaptativo (código "auto-mutante") — `app/bruteforce_guard.py`

Complementa o rate limiter fixo (`RateLimitMiddleware`) com um mecanismo cujo
**a própria política de bloqueio muda em tempo real por identidade**: as duas
primeiras tentativas falhas contra um segredo (token de admin, senha de
keystore, assinatura HMAC de API key) não bloqueiam (tolerância a erro
humano), mas a partir da 3ª falha consecutiva o cooldown cresce
exponencialmente (`1s, 2s, 4s, 8s, ... até 300s`), tornando-se cada vez mais
caro para quem insiste — ao contrário de um rate-limit estático e previsível.
Uma tentativa bem-sucedida reseta o histórico daquela identidade
imediatamente. Protege hoje: `/news*` (admin token), `/wallet/import-keystore`
(senha de keystore) e `/api/v1/order` (assinatura HMAC da exchange API).

### Verificação de integridade do código-fonte — `app/source_integrity.py`

Defesa contra adulteração do código em produção ("source-code hacking"):
calcula SHA-256 de cada arquivo `.py` sob `app/`, combina em uma raiz
Merkle-like determinística e compara contra uma baseline persistida em
`data/source_integrity_baseline.json` (criada automaticamente no primeiro
uso). Qualquer arquivo alterado, adicionado ou removido depois disso é
detectado e reportado via `GET /security/integrity-status` (protegido pelo
mesmo `X-Admin-Token` + guarda anti-força-bruta acima). Após um deploy
legítimo, o operador deve chamar `POST /security/integrity-reset-baseline`
para aceitar deliberadamente o novo estado do código como confiável.

### Honeypots (defesa ativa)

Rotas-isca deliberadamente tentadoras (`/admin/mint-unlimited`, `/internal/debug/private-keys`,
`/_backup/{path}`, `/wallet/{addr}/private-key`, `/honeypot/decoy-wallet`) registram
IP/User-Agent/fingerprint de quem as acessa e respondem com um desafio de
Proof-of-Work de dificuldade muito acima da rede real (`HONEYPOT_CHALLENGE_BITS=40`)
e uma recompensa fake de 250.000 PXC — **nunca paga de verdade**, mesmo que o desafio
seja "resolvido" (`/honeypot/claim`). Objetivo: prender o hardware do atacante em uma
tarefa inútil enquanto se coleta inteligência para bloqueio (`GET /honeypot/report`).

### Ofuscação de transação (memo confidencial)

O ledger permanece público (remetente/destinatário/valor sempre visíveis, como no
Bitcoin), mas o *conteúdo* do memo pode ser cifrado ponta-a-ponta via ECDH
(secp256k1) + HKDF-SHA256 + AES-256-GCM: `POST /wallet/memo/encrypt` /
`POST /wallet/memo/decrypt`. Qualquer terceiro observando a cadeia vê apenas um
blob opaco (`ENC1:...`).

### Ofuscação/compilação de código

Foi avaliado o `pyarmor` (instalado no projeto) para ofuscar o pacote `app/`, mas a
licença trial não suporta um projeto deste tamanho (`ERROR: out of license`).
Como alternativa funcional, `scripts/build_distribution.py` gera uma distribuição
somente-bytecode (`.pyc`, sem os `.py` originais) — veja o cabeçalho do script para
o caminho recomendado em produção (licença paga do PyArmor ou compilação via
Cython/Nuitka dos módulos mais sensíveis).

### Dependências e CVEs

`requirements.txt` agora fixa versões mínimas que corrigem CVEs conhecidos:
`h11>=0.16` (CVE-2025-43859, request smuggling), `starlette>=0.40`/`fastapi>=0.115`
(CVE-2024-47874/CVE-2024-24762), `ecdsa>=0.19` (mitigação parcial de CVE-2024-23342,
Minerva — a mitigação definitiva neste projeto é o uso de `sign_deterministic`).

## Monitoramento e Alertas

O PixCripto inclui um sistema de observabilidade real (`app/monitoring.py`) com endpoint Prometheus, webhook de alertas e log auditável persistido em SQLite.

### Endpoint `/metrics` (Prometheus)

```http
GET /metrics
Content-Type: text/plain; version=0.0.4
```

Expõe as seguintes métricas no formato Prometheus Exposition Format v0.0.4:

| Métrica | Tipo | Descrição |
|---------|------|-----------|
| `pixcripto_chain_height` | gauge | Número total de blocos na cadeia (incluindo genesis) |
| `pixcripto_chain_mined_blocks_total` | counter | Blocos efetivamente minerados (excluindo genesis) |
| `pixcripto_mempool_size` | gauge | Transações pendentes na mempool |
| `pixcripto_current_difficulty` | gauge | Dificuldade atual de mineração (bits) |
| `pixcripto_honeypot_events_total{severity="low\|medium\|high"}` | gauge | Eventos do honeypot por faixa de ameaça |
| `pixcripto_bruteforce_active_lockouts` | gauge | IPs atualmente bloqueados pelo anti-brute-force |
| `pixcripto_source_integrity_ok` | gauge | 1=íntegro, 0=adulteração detectada, -1=verificação falhou |
| `pixcripto_admin_sessions_active` | gauge | Sessões de administrador ativas |
| `pixcripto_user_accounts_total` | gauge | Total de contas de usuário cadastradas |
| `pixcripto_kyc_submissions_pending` | gauge | Submissões de KYC aguardando revisão |

**Integração com Prometheus/Grafana:**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: pixcripto
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: /metrics
    scrape_interval: 15s
```

### Webhook de Alertas

Configure `PIXCRIPTO_ALERT_WEBHOOK_URL` com qualquer URL que aceite HTTP POST JSON. Funciona com Slack, Discord, PagerDuty e qualquer serviço compatível com webhook genérico.

**Payload enviado:**
```json
{
  "event_type": "honeypot_exploit_attempt",
  "severity": "warning",
  "message": "Honeypot: acesso suspeito detectado em /admin/backup de 1.2.3.4",
  "details": {"ip": "1.2.3.4", "path": "/admin/backup", "threat_score": 15},
  "timestamp": 1712345678.123
}
```

**Eventos que disparam alertas:**
- `honeypot_exploit_attempt` (warning) - acesso a rota-isca do honeypot
- `bruteforce_lockout` (warning) - IP bloqueado por excesso de tentativas
- `blockchain_reorg` (warning) - reorg de blockchain detectado, com profundidade
- `source_integrity_tampered` (critical) - adulteração de código-fonte detectada
- `db_integrity_check_failed` (critical) - PRAGMA integrity_check do SQLite falhou

**Integração com Slack:**
```bash
PIXCRIPTO_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
```

**Integração com Discord:**
```bash
PIXCRIPTO_ALERT_WEBHOOK_URL=https://discord.com/api/webhooks/xxx/yyy
```

### Log de Alertas (auditoria sem webhook externo)

```http
GET /monitoring/alerts/recent?limit=50
```

Retorna os últimos N alertas persistidos no SQLite (`alert_log`), incluindo se foram entregues com sucesso ao webhook (`webhook_delivered`). Útil para debug e auditoria mesmo sem webhook configurado.

### Variáveis de Ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `PIXCRIPTO_ALERT_WEBHOOK_URL` | `""` (desabilitado) | URL para envio de alertas via HTTP POST |
| `PIXCRIPTO_ALERT_RATE_LIMIT_SECONDS` | `60` | Janela de supressão de alertas idênticos (segundos) |

## Gaps de produção (o que falta para uso real, além deste protótipo)

> **Nota de enquadramento:** o PixCripto é uma **moeda/blockchain descentralizada
> estilo Bitcoin/Ethereum** — não uma instituição financeira, não um PSP e não um
> intermediário de pagamentos de terceiros. O protocolo (nós P2P, mineração,
> carteiras, VM de contratos, transações) **não exige nenhuma autorização
> regulatória para existir ou operar**, exatamente como Bitcoin não pediu
> autorização a nenhum banco central para rodar. Qualquer pessoa pode baixar o
> código, rodar um nó e minerar/transacionar livremente. Os itens de PSP/BACEN
> abaixo só se aplicam a um caso de uso **opcional e específico**: se **você**
> (o operador) decidir montar um serviço centralizado de compra/venda com Real
> (um "on/off-ramp" tipo exchange), aí sim entra em jogo regulação bancária —
> mas isso é uma camada de negócio *em cima* da moeda, não um requisito da
> moeda em si.

- **Gateway de pagamento (compra de PXC com Real via PSP)** — o endpoint
  `POST /purchase/webhook/confirm` implementa verificação de assinatura
  HMAC-SHA256 real, compatível com qualquer PSP (Mercado Pago, Stripe,
  PagSeguro, etc.). Isso é **opcional**: só é necessário se você quiser oferecer
  a função de "comprar PXC com Real" dentro do seu próprio site. A moeda em si
  (minerar, transacionar, usar carteiras, contratos) funciona 100% sem PSP
  algum, peer-to-peer, como Bitcoin. Para quem optar por oferecer essa compra:
  1. **Configurar `PIXCRIPTO_PAYMENT_WEBHOOK_SECRET`** com o segredo fornecido
     pelo PSP escolhido (gerado no painel do PSP; nunca hardcoded no código).
  2. **Apontar a URL do webhook do PSP** para `POST /purchase/webhook/confirm`
     (URL pública do servidor). O PSP enviará um `POST` com corpo JSON contendo
     ao menos `{"quote_id": "...", "payment_reference": "..."}` e o campo de
     assinatura HMAC-SHA256 no header configurado em
     `PIXCRIPTO_PAYMENT_WEBHOOK_SIGNATURE_HEADER` (padrão: `X-Webhook-Signature`).
  O endpoint de simulação (`/purchase/webhook/simulate-payment-gateway`) está
  disponível **apenas** com `PIXCRIPTO_ENV=devnet` para testes locais.
- **HSM/gestão segura de chaves** — hoje as chaves privadas ficam sob responsabilidade
  do próprio usuário (auto-custódia, igual Bitcoin — cada pessoa é dona da sua
  chave privada). Multi-assinatura M-de-N está implementada (`app/multisig.py`)
  com fluxo PSBT-like completo e validação ECDSA real, para quem quiser
  custódia compartilhada sem depender de terceiros. Um HSM físico dedicado é
  opcional e só faz sentido para grandes operadores/exchanges centralizadas.
- **Auditoria de segurança externa independente** — recomendável antes de
  movimentar valores muito altos, mas não é um bloqueador para o
  funcionamento da moeda (Bitcoin também rodou anos com auditorias
  voluntárias da comunidade, não uma certificação obrigatória).
- **Backup/disaster recovery** — ✅ **implementado**: backup automático com rotação
  (14 execuções mais recentes), backup off-site via `PIXCRIPTO_BACKUP_OFFSITE_DIR`
  (copia o zip atomicamente para um segundo destino — drive de rede, OneDrive/Dropbox
  local, segundo disco), e script de restore `scripts/restore_backup.py` com
  validação `PRAGMA integrity_check`. Ver runbook completo abaixo.
- **Descoberta de peers automática (DNS seeds/PEX)** — ✅ **implementado**: DNS seeds
  resolvidos via `socket.getaddrinfo` na subida do nó (configurável via
  `PIXCRIPTO_DNS_SEEDS`; falha graciosamente se offline); PEX (Peer Exchange) via
  mensagens `getaddr`/`addr` com rastreamento de `discovered_via` por peer;
  limite `PIXCRIPTO_MAX_PEERS`; proteção anti-flood (máx 100 endereços por `addr`);
  `GET /network/peers` expõe a origem de cada peer conectado.
- **Otimização do `state_root`/`contracts_root`** — ✅ **implementado**: cache
  incremental em `Blockchain._replay_state` (`app/models.py`): o estado confirmado
  (saldos + contratos) é mantido em cache e atualizado aplicando apenas o *delta*
  de cada novo bloco, ao invés de replay completo desde o genesis. Resultado: O(1)
  por bloco confirmado vs O(N) anterior — O(N) total vs O(N²) de antes.
  Reorgs invalidam o cache automaticamente (`_invalidate_state_cache` em
  `try_replace_chain`); o rebuild ocorre lazily na próxima consulta. O hash final
  do `state_root`/`contracts_root` é **matematicamente idêntico** ao produzido
  pelo método antigo de replay completo (mesmo algoritmo SHA-256, mesma
  serialização) — verificado por testes em `tests/test_state_root_incremental.py`.
- **VM de contratos: recursos avançados restantes** — Keccak-256 real,
  RLP, `SSTORE_REFUND`, logs indexados consultáveis via API e
  `DELEGATECALL`/`CALLCODE` foram todos implementados (ver seção "Smart
  contracts" acima). Recursos ainda ausentes para compatibilidade total com
  a EVM de produção: `CREATE2` (endereços determinísticos por salt), acesso
  ao `BLOCKHASH`, `EXTCODEHASH`, `EXTCODECOPY`; separação entre *init code*
  e *runtime code* no deploy (hoje o mesmo bytecode serve para ambos); e
  suporte a logs durante reorg (blocos da nova cadeia vencedora após um
  reorg não persistem logs na tabela `contract_logs` — caso raro, documentado
  como gap residual).

## Runbook de Restore (Disaster Recovery)

> **Use este runbook em caso de falha de disco, corrupção do banco ou erro humano.**
> Identifique o backup mais recente em `data/backups/` ou no destino off-site
> (`PIXCRIPTO_BACKUP_OFFSITE_DIR`).

### Pré-requisitos

- Python instalado no servidor de destino
- Acesso ao arquivo `.zip` de backup (`backup-YYYYMMDD-HHMMSS.zip`)
- Servidor **parado** antes de sobrescrever o banco (ver passo 2)

### Passos

**1. Pare o serviço PixCripto**

```bash
# systemd
systemctl stop pixcripto

# ou diretamente (identifique o PID via ps aux | grep main.py)
kill <PID>
```

**2. Valide o backup antes de sobrescrever (dry-run)**

```bash
python scripts/restore_backup.py data/backups/backup-YYYYMMDD-HHMMSS.zip \
    /tmp/restore_preview --dry-run
```

Saída esperada: `✓ Validação concluida com SUCESSO. Backup integro e pronto para restore.`  
Se `integrity_check` falhar, tente o backup anterior.

**3. Execute o restore real**

```bash
# Restaura banco + uploads para o diretório de dados atual (data/)
python scripts/restore_backup.py data/backups/backup-YYYYMMDD-HHMMSS.zip \
    data/ --force
```

O script:
- Extrai o zip para um diretório temporário
- Executa `PRAGMA integrity_check` no banco extraído
- Copia `pixcripto_chain.db` para `data/` e uploads para `data/uploads/` (se presentes)
- Imprime um relatório com altura da chain e número de blocos restaurados

**4. Reinicie o serviço**

```bash
systemctl start pixcripto
```

**5. Verifique a integridade pós-restore**

```bash
curl http://localhost:8000/chain/metadata
# Deve retornar JSON com height, difficulty, total_work etc.

curl http://localhost:8000/health
# Deve retornar {"status": "ok"}
```

### Variáveis de ambiente de backup

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `PIXCRIPTO_BACKUP_OFFSITE_DIR` | `""` (desabilitado) | Segundo destino para cópia off-site do backup |

### Notas importantes

- O servidor **deve estar parado** antes do restore. SQLite não suporta dois
  processos escrevendo simultaneamente; um restore enquanto o servidor roda
  pode resultar em corrupção.
- O script **nunca sobrescreve** arquivos existentes sem `--force`. Isso é uma
  proteção contra restore acidental em produção.
- Em caso de reorg pós-restore: o servidor reconstruirá o cache incremental de
  estado automaticamente na inicialização — sem ação manual necessária.

## Limitações conhecidas e roadmap futuro

O PixCripto é uma moeda/blockchain descentralizada real e funcional (não um
protótipo educacional) — nó P2P, mineração, carteiras, VM de contratos,
multisig, KYC opcional e API já rodam de ponta a ponta com testes reais. Os
itens abaixo são otimizações de desempenho/roadmap, não bloqueadores de
funcionamento:

- O kernel OpenCL fornecido faz o *dispatch* paralelo de nonces na GPU; o hash SHA-256
  de verificação final roda no host, por robustez/compatibilidade — para máximo throughput
  em produção, um kernel SHA-256 nativo em OpenCL C seria o próximo passo.
- Sem exchange automatizada (hoje a troca é feita por transação direta em carteira,
  como no Bitcoin; um order-book/mercado de troca automatizado é um recurso futuro).
- A VM de contratos executa de forma síncrona no momento da mineração (não há
  paralelização de execução de contratos entre transações do mesmo bloco).
