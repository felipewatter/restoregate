# Registro de validação local — RestoreGate v0.1.0

**Data do teste:** 2026-11-08  
**Ambiente local:** Linux, CPython 3.13.5  
**Escopo:** versão candidata **antes** de criar repositório remoto e release.

## Verificações executadas

| Verificação | Resultado |
| --- | --- |
| `python -m compileall -q src tests` | Aprovado |
| `PYTHONPATH=src python -m unittest discover -s tests -q` | 56 testes, 0 falhas |
| `PYTHONPATH=src python -m pytest -q` | 56 testes, 0 falhas |
| `python -m pip install --no-deps --no-build-isolation . --target /tmp/restoregate-installed` | Aprovado |
| `PYTHONPATH=/tmp/restoregate-installed python -m restoregate --version` | RestoreGate 0.1.0 |
| `python -m pip wheel --no-deps --no-build-isolation .` | Wheel construído |
| `zipfile.ZipFile(...).testzip()` no pacote fonte | Sem membro corrompido |
| Parsing local dos arquivos YAML de workflows | Aprovado sintaticamente (não equivale à validação do GitHub) |

**Classes cobertas:** leitura ZIP/TAR e TAR.GZ, `scan`, `drill`, releitura/hash, limpeza temporária, caminhos absolutos e `../`, Windows/Unicode, links ZIP/TAR, dispositivos, entradas duplicadas/casefold, conflito arquivo-diretório, limites de membros/profundidade/tamanho/razão, idade, arquivos obrigatórios, formatos corrompidos ou desconhecidos, alteração do backup durante leitura, política inválida, JSON/SARIF, escrita atômica, CLI em subprocesso.

## Pendências intencionais

- **GitHub Actions:** ainda não iniciado; 12 combinações (3 sistemas operacionais × 4 versões Python) precisam ser validadas na plataforma após publicação autorizada.
- **GitHub Release:** não criado; o workflow manual só deve ser executado **depois de todas as verificações CI finalizarem com sucesso**.
- **Ambientes não disponíveis localmente:** a execução direta em Windows/macOS e Python 3.10/3.11/3.12 depende dos runners GitHub Actions.
- **Auditoria externa:** nenhuma alegação de certificação formal, pentest independente ou revisão de segurança por terceiros.

Esta evidência não substitui a verificação remota nem garante ausência de vulnerabilidades.
