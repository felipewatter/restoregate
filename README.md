# RestoreGate

[![CI](https://github.com/felipewatter/restoregate/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/restoregate/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)

**RestoreGate** é um mecanismo de verificação **offline** de prontidão para recuperação de arquivos de backup. Em vez de apenas confirmar que um ZIP ou TAR existe, ele verifica sua estrutura, lê seus conteúdos sob limites de recursos, identifica sinais de risco e, sob comando explícito, executa um **restore drill** isolado: restaura os arquivos em um diretório temporário, relê cada arquivo e compara o SHA-256 com o conteúdo previamente inspecionado.

> **Estado:** v0.1.0 — implementação inicial. O selo de CI acima só refletirá execuções reais **depois da publicação e da execução do GitHub Actions**; nenhum resultado remoto é presumido.

[English documentation](README.en.md) · [Arquitetura](docs/ARCHITECTURE.md) · [Validação local](docs/VALIDATION.md) · [Modelo de ameaças](docs/THREAT_MODEL.md) · [Política de segurança](SECURITY.md) · [Histórico](CHANGELOG.md)

## Por que existe?

Um job de backup bem-sucedido não comprova que o conteúdo é utilizável durante a recuperação de um incidente. Problemas comuns incluem arquivos corrompidos, ausência de arquivos obrigatórios, formatos ambíguos, backups antigos e pacotes com caminhos perigosos. Há também risco de **Zip Slip**, links simbólicos e arquivos com descompressão desproporcional. O RestoreGate transforma esses problemas em falhas explícitas e evidências consumíveis por uma equipe de infraestrutura ou pipeline CI.

O RestoreGate **não cria backups** nem substitui Restic, BorgBackup, Kopia, ferramentas de DR ou testes integrais de aplicações e bancos de dados. Ele é uma camada adicional, independente, para backups no formato de arquivo suportado.

## Recursos implementados

| Capacidade | Como funciona |
| --- | --- |
| ZIP e TAR | Suporta `.zip`, `.tar`, `.tar.gz`, `.tar.bz2` e `.tar.xz` por detecção de conteúdo, não apenas extensão |
| Inspeção segura | Recusa travessia de diretórios, caminhos absolutos, barras invertidas, ADS NTFS, nomes reservados Windows e ambiguidades Unicode NFC |
| Segurança de membros | Recusa links, dispositivos e tipos especiais; detecta nomes duplicados, conflitos entre arquivos e pastas e colisões ignorando maiúsculas/minúsculas |
| Limites de recursos | Restringe tamanho do pacote, de cada arquivo, volume descompactado, profundidade, quantidade de membros e razão de compressão ZIP |
| Verificação integral | Consome cada arquivo em blocos de 64 KiB; valida tamanho real, erros de leitura e CRC do ZIP; gera hash SHA-256 do arquivo compactado |
| Recuperação isolada | Com `drill`, faz a restauração em diretório temporário privado, compara os hashes da primeira leitura e relê cada arquivo restaurado |
| Políticas declarativas | JSON com limites, idade máxima baseada em `mtime`, número mínimo de arquivos e caminhos obrigatórios |
| Evidência automatizável | Saída humana ou JSON estruturado, SARIF 2.1.0, códigos de saída definidos e escrita atômica de relatórios |
| Execução offline | Apenas biblioteca padrão do Python, sem API, credenciais, rede ou telemetria |

**Distinção entre modos:** `scan` não extrai arquivos; `drill` escreve **somente** em um diretório temporário, que é removido após a operação, mesmo quando ocorre falha. Nenhum modo executa o conteúdo extraído ou substitui arquivos do sistema.

## Requisitos

- Python **3.10 ou superior** (Windows, macOS, Linux).
- Sem dependências de execução. Para instalar via `pip`, utilize um ambiente Python com `setuptools` disponível para build.
- Espaço livre no diretório temporário suficiente para os dados que o `drill` restaurará (regulado pela política).

## Instalação

```bash
# A partir do código-fonte clonado
python -m pip install .
restoregate --version
```

Também é possível executar **sem instalar**, a partir da raiz do repositório:

```bash
# Linux/macOS
PYTHONPATH=src python -m restoregate --help

# Windows (PowerShell)
$env:PYTHONPATH = 'src'
python -m restoregate --help
```

## Uso rápido

```bash
# 1. Inspeção sem extração
restoregate scan /backups/servidor-2026-11-08.zip

# 2. Restaurar temporariamente, reler, comparar e remover a cópia de ensaio
restoregate drill /backups/servidor-2026-11-08.zip

# 3. Política corporativa + evidências JSON/SARIF
restoregate drill /backups/servidor-2026-11-08.zip \
  --policy examples/policy.json \
  --json-out resultado.json \
  --sarif-out resultado.sarif \
  --format json
```

**Nota:** `examples/policy.json` é deliberadamente restritiva: exige `database/dump.sql` e `configs/app.conf`, no mínimo dois arquivos e backup com menos de 7 dias. Modifique os caminhos para o seu próprio backup. Não utilize dados reais em issues públicas.

### Exemplo de relatório JSON

```json
{
  "archive": "/backups/servidor.zip",
  "archive_sha256": "<sha256-da-midia>",
  "bytes_checked": 1024,
  "directories_checked": 1,
  "files_checked": 2,
  "findings": [],
  "format": "zip",
  "mode": "drill",
  "ok": true,
  "policy": { "...": "demais campos da política aplicada" },
  "restored_bytes": 1024,
  "restored_files": 2,
  "schema_version": "1.0"
}
```

O trecho acima é **ilustrativo**; valores reais são gerados a partir de um arquivo analisado. Quando uma condição de segurança falha, `findings` registra código, mensagem e caminho quando disponível; `ok` passa a `false`.

### Códigos de saída

| Código | Significado |
| --- | --- |
| `0` | Arquivo aprovado e, em `drill`, restauração/releitura concluída |
| `1` | Arquivo inválido, inseguro ou reprovado por política / falha operacional de leitura |
| `2` | Erro na configuração de política ou na escrita de evidências |

Os relatórios **não são assinados digitalmente**. Trate-os como evidência operacional produzida por um processo confiável, não como prova criptográfica independente.

## Referência de políticas

Os valores padrão são conservadores para demonstração e devem ser ajustados ao tamanho dos seus backups:

| Chave | Valor padrão | Unidade/propósito |
| --- | --- | --- |
| `max_archive_bytes` | 1.073.741.824 | Bytes máximos do arquivo de backup |
| `max_total_bytes` | 1.073.741.824 | Bytes totais descompactados |
| `max_file_bytes` | 268.435.456 | Bytes por arquivo |
| `max_members` | 10.000 | Quantidade máxima de membros |
| `max_ratio` | 200 | Razão máxima descompactado/comprimido **por membro ZIP** |
| `max_depth` | 32 | Profundidade máxima dos caminhos |
| `max_age_hours` | `null` | Idade máxima do arquivo com base em `mtime`; `null` desativa |
| `min_files` | 1 | Mínimo de arquivos regulares |
| `required_paths` | `[]` | Arquivos que devem existir (caminho exato) |

**Validação estrita:** chaves desconhecidas, tipos incorretos, números não positivos e caminhos inseguros são recusados antes da leitura do arquivo. O controle de razão de compressão é implementado para ZIP; arquivos TAR compactados continuam sujeitos a limites de tamanho total/descompactado, mas não recebem um cálculo de razão por membro.

## Qualidade, testes e CI

```bash
python -m compileall -q src tests
python -m unittest discover -s tests -v
# Suíte compatível com pytest (opcional)
python -m pytest -q
```

O workflow `.github/workflows/ci.yml` executa uma matriz de **Python 3.10–3.13** em **Linux, Windows e macOS**: compilação, testes unitários e testes adversariais, mais smoke test de CLI. Usa permissões mínimas e actions com commits fixos por SHA; Dependabot acompanha as actions. **Não confundir testes locais com GitHub Actions:** o status remoto precisa ser verificado após a publicação.

## Integração de operação

Para fazer do RestoreGate um controle de pipeline, execute `restoregate drill backup.zip --policy policy.json --json-out evidence.json --sarif-out evidence.sarif` em uma máquina isolada com recursos definidos. Publique apenas **evidências sanitizadas** para evitar vazamento de nomes internos. Retorne código diferente de zero para reprovar a etapa e encaminhe o código do finding para atendimento técnico.

**Integração GitHub Actions de exemplo:**

```yaml
- name: Validar recuperabilidade de backup sintético
  env:
    PYTHONPATH: src
  run: python -m restoregate drill fixtures/backup-sintetico.zip --format json
```

Crie um ZIP sintético em um passo anterior, pois **este repositório não versiona backups nem fixtures binárias**. A configuração fornecida não transfere seus backups para terceiros.

## Limitações e garantias que não oferece

- Não testa a restauração lógica de PostgreSQL, MySQL, máquinas virtuais, imagens de sistema ou consistência transacional; prova apenas a recuperação byte a byte dos arquivos suportados.
- Não detecta malware, não descriptografa ZIPs e não protege backups contra ransomware por si só.
- Não garante RTO/RPO, disponibilidade da infraestrutura de destino, restauração de permissões/ACLs, proprietário, timestamps nem links (deliberadamente recusados).
- Não protege contra modificação maliciosa do arquivo **antes** da inspeção. O SHA-256 produzido identifica a versão examinada, sem comparar com uma âncora externa confiável.
- `mtime` pode ser alterado e **não** comprova a data verdadeira do backup.
- Limites definidos **não substituem** isolamento de CPU/tempo/disco no host. Use container/VM com quotas para arquivos não confiáveis.
- Os relatórios incluem caminhos de membros do backup; mantenha-os privados quando necessário.

## Estrutura do repositório

```text
src/restoregate/
  __init__.py          Versão do pacote
  __main__.py          Entrada com python -m restoregate
  cli.py               Parser, códigos de saída, relatórios
  core.py              ZIP/TAR, limites, hashes, restore drill
  paths.py             Normalização e bloqueio de caminhos inseguros
  policy.py            Política JSON estrita
  report.py            Estruturas de evidência, JSON e SARIF
examples/policy.json  Exemplo de política
 tests/                Testes unitários, integração CLI e casos adversariais
 docs/                 Arquitetura, ameaças e processo de publicação
 .github/              CI, Dependabot e modelos para colaboração
```

## Contribuições, segurança e licença

PRs são bem-vindos; leia [CONTRIBUTING.md](CONTRIBUTING.md). Reporte possíveis vulnerabilidades seguindo [SECURITY.md](SECURITY.md), sem revelar detalhes exploráveis em issues públicas. Licenciado sob **MIT** ([LICENSE](LICENSE)). Criado por **Felipe Silva** — [@felipewatter](https://github.com/felipewatter).

## Referências

- [NIST — Contingency Planning Guide for Federal Information Systems (SP 800-34 Rev. 1)](https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final)
- [NIST — Protecting Data from Ransomware and Other Data Loss Events (MSP backup guidance)](https://csrc.nist.gov/pubs/other/2020/04/24/protecting-data-from-ransomware-and-other-data-los/final)
- [CISA — #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
- [OWASP — File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP — Web Security Testing Guide: Upload of Malicious Files](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic/09-Upload_of_Malicious_Files/)
- [Python — zipfile](https://docs.python.org/3/library/zipfile.html) e [tarfile](https://docs.python.org/3/library/tarfile.html)
