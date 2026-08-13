# 📜 Book of Rules — PixCripto (PXC)

> Versão do Book of Rules: **1.4.0** (corresponde a `root_rules.RULES_VERSION`)
> Hash canônico das regras: consulte `GET /rules/root-hash` em tempo de execução.
>
> Este documento é a tradução em linguagem humana do arquivo `app/root_rules.py`,
> que é a **única fonte da verdade** em código. Em caso de qualquer divergência
> entre este texto e `root_rules.py`, **o código prevalece** — mas essa divergência
> é, por definição, um bug de documentação a ser corrigido, nunca o contrário.
> Qualquer alteração em uma constante de `root_rules.py` muda o `root_hash` e deve
> vir acompanhada de um incremento de versão aqui (ver seção 10).

---

## 1. Identidade da rede

| Campo | Valor |
|---|---|
| Nome da rede | PixCripto |
| Símbolo | PXC |
| Byte de versão de endereço (mainnet) | `0x37` |
| Byte de versão de endereço (testnet) | `0x6F` |
| Formato de endereço | Base58Check, idêntico em estrutura ao Bitcoin (payload = RIPEMD160(SHA256(pubkey)), com checksum duplo-SHA256) |
| Formato de carteira | Chave privada secp256k1 (mesma curva do Bitcoin/Ethereum), WIF opcional para exportação/importação |

## 2. Regras econômicas (emissão / suprimento)

PixCripto **não é escasso por design** (diferente do Bitcoin, que tem teto de 21M).
Isso foi uma decisão explícita do idealizador do projeto: o PXC deve ser **comprável
sob demanda** para uso como meio de pagamento do dia a dia, não como reserva de valor
puramente especulativa. Para isso não gerar hiperinflação instantânea, existem
tetos de emissão por unidade de tempo:

- **Sem teto absoluto de suprimento** (`MAX_SUPPLY_HARD_CAP = None`).
- **Teto de emissão por bloco**: 100.000 PXC (mineração + compra combinadas).
- **Teto de emissão agregada por hora**: 2.000.000 PXC (janela deslizante).
- **Recompensa de mineração**: 4% do valor total do bloco minerado vai para o
  minerador/validador que resolver o Proof-of-Work primeiro (dividido
  proporcionalmente entre validadores em mineração colaborativa/pool).
- **Taxa de compra**: 7,38% cobrados a cada R$ 100 comprados (spread de emissão,
  cobre custo operacional e desincentiva compra puramente especulativa em massa).
- **Lastro em ouro**: 1 PXC representa uma fração fixa de 0,00025 oz de ouro
  (XAU). O preço em BRL acompanha automaticamente XAU/USD × USD/BRL, protegendo
  o poder de compra real da moeda contra desvalorização cambial pura.

## 3. Regras de dificuldade / mineração (Proof-of-Work)

- A dificuldade **cresce 20× a cada 2 blocos minerados**, matematicamente, até um
  teto configurável:
  - Modo `demo`: teto de 21 bits (mineração viável em hardware comum, para testes).
  - Modo `mainnet_like`: teto de 76 bits (aproximadamente equivalente à
    dificuldade da rede Bitcoin por volta de 2020).
- **Anti-monopólio de hash-power**: a cada bloco, o sistema calcula a participação
  recente do minerador (janela de 20 blocos) e vetoriza uma penalidade adicional de
  dificuldade (`alpha`) proporcional a essa participação — quanto mais um único
  minerador/pool domina blocos recentes, mais difícil fica para ele especificamente
  minerar o próximo bloco (até um teto de penalidade de 24 bits extras). Isso
  desestimula a centralização de poder de hash sem impedir mineração honesta.
- **GPU como fonte primária de mineração**: a API oferece um motor de mineração
  otimizado com suporte a CUDA (NVIDIA) e OpenCL/ROCm (AMD), com fallback CPU.
- Metadados de cada hash minerado (nonce, dificuldade efetiva, participação do
  minerador) são persistidos e usados para ajustar cálculos futuros de dificuldade.

## 4. Regras de transação

- Valor mínimo: 0.00000001 PXC (1 "satoshi-PXC", 8 casas decimais).
- Valor máximo por transação: 10.000.000 PXC (teto de sanidade anti-overflow/DoS).
- Memo (mensagem opcional): até 512 bytes.
- Cada endereço pode ter no máximo 50 transações pendentes simultâneas na mempool
  (anti-flood).
- Transações pendentes expiram da mempool após 24h se não forem mineradas.
- Tipos de transação reconhecidos pelo protocolo (whitelist estrita — qualquer
  outro valor é rejeitado): `transfer`, `coinbase_mining`, `coinbase_purchase`,
  `sell_burn`, `liquidation_burn`, `swap_escrow`, `swap_fill`,
  `swap_cancel_refund`, `rollup_commit`, `l2_withdrawal`, `contract_deploy`,
  `contract_call`.
- Transações `contract_deploy`/`contract_call` carregam um campo adicional
  `data` (bytecode/calldata em hex), limitado a `MAX_CONTRACT_BYTECODE_BYTES`
  (24.576 bytes, mesmo teto prático do EIP-170 do Ethereum) e
  `MAX_CONTRACT_CALLDATA_BYTES` (16.384 bytes) respectivamente. O campo `fee`
  dessas transações é interpretado como orçamento de gas, convertido para
  unidades de gás pela constante `GAS_PRICE_PXC` (preço fixo de 1 unidade de
  gás em PXC) — todo o valor de `fee` é debitado do remetente independente do
  gás realmente consumido (sem reembolso estilo EIP-1559).
- Endereços de sistema (`SISTEMA_EMISSAO`, `PXC_L2_BRIDGE_ESCROW`,
  `PXC_SWAP_ESCROW_POOL`) nunca podem aparecer como remetente de uma transação
  do tipo "assinada pelo usuário" (`transfer`) — apenas o próprio protocolo pode
  gerar transações a partir desses endereços, e apenas para os tipos corretos.
- **Validação de tempo do bloco**: um bloco não pode ter timestamp mais de 120s no
  futuro em relação ao relógio do nó que o recebe, nem retroceder mais de 60s em
  relação ao bloco anterior — protege o recálculo de dificuldade contra
  manipulação via timestamps forjados.

## 5. Controle de dump / auto-regulação ("self-leaving system")

A moeda se auto-regula para não saturar sua escalabilidade nem destruir seu
próprio valor de mercado:

- Janela de observação de dump: 600 segundos (10 minutos).
- Nenhuma carteira pode vender/liquidar mais que 30% do seu saldo dentro dessa
  janela — protege contra "rug pulls" individuais.
- A rede como um todo tem um piso e um teto de proporção de dump permitido
  (1% a 8% do supply circulante estimado por janela) — se a pressão vendedora
  agregada ultrapassar o teto, novas operações de venda/liquidação são
  recusadas até a janela normalizar, dando tempo ao mercado para absorver o
  impacto sem colapso de preço.

## 6. Regras de rede / API (anti-abuso)

- Rate limit: 60 requisições por IP por rota sensível por minuto.
- Iterações de mineração por chamada (`/mining/mine`): máximo de 5.000.000 (evita
  DoS via chamadas que travam o processo por tempo indefinido).
- Circuit breaker do oráculo de ouro: qualquer cotação que varie mais de 15% em
  relação ao último valor confiável é rejeitada automaticamente (proteção contra
  MITM/API comprometida manipulando o preço do lastro).

## 7. Segurança criptográfica

- Curva: secp256k1 (idêntica a Bitcoin/Ethereum).
- Assinatura: ECDSA **determinística** (RFC 6979) — elimina o risco de nonce
  fraco/reutilizado (classe de vulnerabilidade explorada por ataques como
  Minerva, CVE-2024-23342).
- Chaves privadas **nunca devem transitar pela rede em produção**: o endpoint
  recomendado é `/transaction/submit-signed`, que recebe apenas a assinatura e a
  chave pública, nunca a chave privada. O endpoint `/transaction/send` (que
  aceita a chave privada) existe apenas como conveniência de demonstração e é
  explicitamente documentado como tal.
- Toda validação de endereço confere que a chave pública corresponde a um ponto
  válido na curva secp256k1 antes de aceitá-la.
- **Ofuscação de transação (memo confidencial)**: o ledger permanece público e
  auditável (remetente/destinatário/valor sempre visíveis, como no Bitcoin),
  mas o *conteúdo* do memo pode ser cifrado ponta-a-ponta via ECDH (secp256k1)
  + HKDF-SHA256 + AES-256-GCM (`crypto_utils.encrypt_memo`/`decrypt_memo`,
  endpoints `/wallet/memo/encrypt` e `/wallet/memo/decrypt`). Qualquer terceiro
  observando a cadeia vê apenas um blob opaco (`ENC1:...`); somente remetente e
  destinatário conseguem decifrar.

## 7-A. Smart contracts / máquina virtual (consenso)

- Transações `contract_deploy`/`contract_call` só executam de fato quando um
  bloco as inclui na mineração (nunca no momento de aceitação na mempool) —
  a execução é **determinística** e replicável por qualquer nó via replay
  completo da cadeia.
- `contracts_root`: novo campo do cabeçalho do bloco, coberto pelo hash
  minerado (Proof-of-Work) igual ao `state_root` — hash SHA-256 do snapshot
  de código+storage de todos os contratos após aquele bloco. Um bloco cujo
  `contracts_root` não bate com o replay determinístico é rejeitado por
  qualquer nó (`is_chain_valid`/`validate_candidate_chain`).
- Padrão **Checks-Effects-Interactions** obrigatório na VM: mutação de
  storage (`SSTORE`) sempre ocorre antes de qualquer sub-chamada (`CALL`),
  com uma guarda de reentrância que impede um contrato de reentrar em si
  mesmo durante uma `CALL` ativa.
- **Rollback atômico**: `REVERT` e qualquer exceção durante a execução
  desfazem por completo (via snapshot/restore por frame) todo `SSTORE`,
  `CREATE`, `SELFDESTRUCT` e transferência de saldo daquele frame — inclusive
  aninhado através de `CALL`s recursivas.
- **Reembolso de gás não utilizado** (`gas_limit - gas_used`) creditado de
  volta ao remetente após a execução (seção 5.3 do guia).
- `SHA3` e o endereço determinístico de deploy usam SHA-256 (não Keccak256)
  — reaproveita o mesmo primitivo criptográfico já usado no resto do
  protocolo, mesma robustez, sem depender de biblioteca extra.
- Ver `README.md`, seção "Smart contracts / máquina virtual", para a lista
  completa de opcodes e demais simplificações documentadas.



Rotas-isca (`/admin/...`, `/internal/...`, `/_backup/...`, tentativas de
"recuperar chave privada por endereço") existem deliberadamente para atrair
tentativas de exploração. Qualquer acesso:

1. É registrado (IP, User-Agent, fingerprint, timestamp, rota, score de ameaça).
2. Recebe um desafio de Proof-of-Work com dificuldade muito acima da rede real e
   uma recompensa fake (nunca paga de verdade em lugar algum do ledger real).
3. Alimenta um painel de reputação (`GET /honeypot/report`) para bloqueio futuro
   via firewall/WAF real.

Nenhum honeypot jamais expõe fundos reais nem chaves privadas reais.

## 9. Transparência e consulta pública

Qualquer pessoa pode consultar, sem autenticação:

- `GET /chain` — a cadeia completa de blocos.
- `GET /chain/metadata` — dificuldade atual, contagem de blocos, hash do último bloco.
- `GET /wallet/{address}/balance` — saldo de qualquer endereço público.
- `GET /market/*` — atividade de mercado, ordens de swap abertas, concentração
  de carteiras (HHI), preço do ouro/PXC.
- `GET /rules/root-hash` — snapshot assinado (hash) de todas as regras de consenso ativas.
- `GET /rules/book` — este documento, servido programaticamente.

Isso cumpre o requisito de "consulta de movimentação de carteiras": qualquer
observador pode acompanhar o movimento real do mercado, mas **nenhuma chave
privada é jamais exposta** — apenas chaves públicas/endereços e valores.

## 10. Governança e histórico de versões

Qualquer alteração em uma constante de `root_rules.py` é, por definição, um
**hard fork** e exige:

1. Incrementar `RULES_VERSION`.
2. Registrar a mudança nesta seção, com data e justificativa.
3. Definir um bloco de ativação a partir do qual a nova regra passa a valer
   (nunca retroativo).

### Histórico

- **1.4.0** — correção da recompensa de mineração: `MINER_REWARD_RATE` alterado
  de 0,4% para **4%** do valor do bloco, para refletir corretamente o pedido
  original do usuário (a recompensa dividida entre validadores em mineração
  colaborativa sempre foi especificada como "4% dividido entre os usuários
  que fizeram a validação"; a versão 1.3.0 implementou o mecanismo de divisão
  proporcional corretamente, mas com a taxa-base errada). Mudança puramente
  no parâmetro econômico `MINER_REWARD_RATE` — nenhuma mudança estrutural em
  `Block`/`Transaction`. Como a recompensa é uma transação de coinbase
  coberta pelo Proof-of-Work, é uma mudança de consenso e exige bump de
  versão. Bloco de ativação: a partir do primeiro bloco minerado após o
  deploy desta versão (blocos já minerados com a taxa de 0,4% permanecem
  válidos e não são recalculados retroativamente).
- **1.3.0** — mineração colaborativa (pool mining): `build_candidate_block()`
  passa a aceitar uma lista opcional de `contributors` (endereço + peso/shares),
  dividindo a recompensa de 4% do bloco proporcionalmente entre TODOS os que
  participaram da validação, em vez de sempre ir 100% para um único
  `miner_address` — mesmo espírito de um pool de mineração Bitcoin real.
  Novas constantes de consenso: `MAX_POOL_CONTRIBUTORS_PER_BLOCK` (500, limite
  anti-spam do payload do bloco) e `MIN_POOL_CONTRIBUTOR_SHARE` (1e-9, rejeita
  pesos degenerados/zero). Endpoints `/mining/mine` e `/mining/submit-proof`
  ganham o campo opcional `pool_contributors` e a resposta passa a incluir
  `reward_breakdown` (crédito exato por endereço). Quando `pool_contributors`
  é omitido, o comportamento é idêntico ao legado (retrocompatível). Como a
  divisão da recompensa é registrada em transações de coinbase dentro do
  próprio bloco (cobertas pelo Proof-of-Work), esta é uma mudança de consenso
  e exige o bump de versão. Bloco de ativação: a partir do primeiro bloco
  minerado após o deploy desta versão (nenhum bloco já minerado é afetado
  retroativamente).
- *(sem bump de versão)* — ecossistema operacional completo adicionado:
  conformidade regulatória própria (KYC/AML, `app/compliance.py`), API estilo
  Binance para integração externa (`app/exchange_api.py`), configuração
  central de ambiente/rede/DNS (`app/settings.py`, `app/network_config.py`),
  UI web de carteira (`app/templates/`, `app/static/`) e painel de
  administração separado (`admin_panel/`, nunca compilado na distribuição).
  Nenhuma dessas mudanças altera `root_rules.py`, `state_root` ou
  `contracts_root` — são puramente operacionais/de integração, não afetam o
  consenso da rede, por isso **não exigem** incremento de `RULES_VERSION`.
- **1.2.0** — auditoria completa e reescrita da VM de smart contracts
  (`app/vm.py`) para cobrir os gaps identificados contra a seção 5/FASE 6 do
  guia: rollback **atômico** real via snapshot/restore por frame de chamada
  (antes, `REVERT`/exceções não desfaziam `SSTORE`/`CREATE`/`SELFDESTRUCT`/
  saldos — corrigido); **reembolso do gás não utilizado** ao remetente (seção
  5.3); ~20 novos opcodes (`ADDMOD`, `MULMOD`, `EXP`, `NOT`, `BYTE`, `SHL`,
  `SHR`, `SAR`, `ORIGIN`, `CALLDATASIZE`, `CALLDATACOPY`, `CODESIZE`,
  `CODECOPY`, `GASPRICE`, `EXTCODESIZE`, `RETURNDATASIZE`,
  `RETURNDATACOPY`, `TIMESTAMP`, `NUMBER`, `MSIZE`, `GAS`, `STATICCALL`);
  transferência real de saldo PXC em `CALL`/`CREATE` com `value` (antes
  apenas simulada); `CREATE` agora executa o bytecode implantado como
  construtor e desfaz o deploy inteiro se ele reverter; `MAX_CALL_DEPTH`
  reduzido de 1024 para 200 (margem de segurança contra o limite de
  recursão do Python, já que a VM usa recursão real do interpretador);
  novo limite físico de memória por execução (`MAX_MEMORY_BYTES`, 1 MiB)
  como defesa em profundidade. Alterações de comportamento da VM afetam o
  `contracts_root`/`state_root` (consenso), por isso o bump de versão.
- **1.1.0** — adiciona os tipos de transação `contract_deploy`/`contract_call`
  e a máquina virtual de smart contracts (`app/vm.py`), com o novo campo de
  cabeçalho `contracts_root` (coberto pelo Proof-of-Work) e as constantes
  `GAS_PRICE_PXC`, `MAX_CONTRACT_BYTECODE_BYTES`, `MAX_CONTRACT_CALLDATA_BYTES`.
  Também documenta (sem exigir mudança de consenso) a rede P2P real
  (`app/network.py`), a carteira HD/seed-phrase (`app/hd_wallet.py`) e o
  JSON-RPC 2.0 + WebSocket (`app/rpc.py`, `app/ws_hub.py`) — ver `README.md`
  para detalhes de cada um.
- **1.0.0** — versão inicial do Book of Rules. Consolida todas as regras
  aplicadas durante a rodada de auditoria de segurança (correção de mint
  arbitrário via compra, roubo de escrow de swap, replay de depósito L2,
  validação de timestamp de bloco, assinatura determinística ECDSA, entre
  outras — ver `README.md`, seção de segurança, para o changelog técnico completo).

---

## 11. O que este sistema **não é** (limitações conhecidas, para transparência)

Para ser uma blockchain "de utilização real" no sentido pleno, faltam ainda
(ver `README.md` → "Gaps de produção" para detalhes):

- Descoberta automática de peers (DNS seeds/PEX) — a rede P2P
  (`app/network.py`) já existe e funciona (handshake, gossip, IBD, reorg por
  trabalho acumulado), mas a lista de peers iniciais precisa ser informada
  manualmente hoje.
- Integração com um gateway de pagamento real (hoje o fluxo de compra usa um
  webhook simulado para fins de demonstração).
- Ofuscação/compilação do código-fonte Python para uma distribuição binária
  (avaliado `pyarmor`, mas a licença trial não permite ofuscar um projeto deste
  tamanho — `ERROR: out of license`). Alternativas viáveis para uma implantação
  real: licença paga do PyArmor, compilação via Cython/Nuitka, ou distribuição
  apenas do bytecode (`.pyc`) via `python -m compileall`. A ofuscação de
  **transação** (conteúdo do memo) já está implementada de verdade via
  ECDH + AES-256-GCM (ver seção 7).
- A VM de contratos (`app/vm.py`) não implementa Keccak256/RLP (usa SHA-256 e
  um esquema de endereçamento próprio, ver seção 7-A e `README.md`). O
  reembolso do gás **não utilizado** já é implementado, mas não há o refund
  *específico* de zerar um slot de `SSTORE` (equivalente ao `SSTORE_REFUND`
  clássico da EVM), nem `DELEGATECALL`/`CALLCODE`, nem um endpoint de consulta
  de logs/eventos indexados (os opcodes `LOG0`-`LOG4` executam, mas não há
  índice consultável ainda).
- Auditoria de segurança externa independente.
- Conformidade regulatória (KYC/AML, autorização como instituição de pagamento)
  para operação legal como meio de pagamento no Brasil.
