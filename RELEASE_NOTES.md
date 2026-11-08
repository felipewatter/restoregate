# RestoreGate v0.1.0 — primeira versão

Lançamento inicial do **RestoreGate**, uma ferramenta CLI offline de verificação de prontidão para recuperação de arquivos de backup ZIP/TAR.

## Destaques

- Inspeção estrutural segura: travessia de diretórios, nomes incompatíveis entre sistemas, colisões, links simbólicos, tipos especiais e limites de recursos.
- Validação de conteúdo por streaming em blocos, CRC ZIP e hash SHA-256 do pacote.
- `restoregate drill`: restauração temporária isolada com conferência e releitura de todos os arquivos.
- Política declarativa JSON: mínimos, obrigatórios, limites e idade opcional.
- Relatórios JSON e SARIF, códigos de saída para pipelines e documentação em português/inglês.
- GitHub Actions com matriz de 12 combinações de Python/OS e testes adversariais automatizados.

## Compatibilidade

Python 3.10+; Windows, Linux e macOS; sem dependências de runtime.

## Atenção

O RestoreGate não substitui backups, não valida consistência transacional de bancos, não é antivírus e não garante recuperação completa de sistemas. Utilize-o como etapa complementar de um programa de continuidade de TI.

Consulte [README.md](README.md), [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) e [LICENSE](LICENSE).
