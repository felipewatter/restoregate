# Arquitetura e fluxo de confiança

## Componentes

1. `cli.py`: parâmetros explícitos, leitura de política, saída e exit codes.
2. `policy.py`: esquema fechado de política. Rejeita atributos desconhecidos, tipos não esperados, floats não finitos e caminhos obrigatórios inseguros.
3. `paths.py`: nomes de arquivo tratados como dados não confiáveis. Regras portáveis entre plataformas; rejeita caminhos ambíguos em vez de tentar consertá-los.
4. `core.py`: abre arquivo suportado, calcula SHA-256 do backup, faz inventário, checa membros e limites, lê cada arquivo em blocos, executa opcionalmente um segundo passe de extração controlada e releitura.
5. `report.py`: findings determinísticos JSON/SARIF, sem dependência de um serviço externo.

## Fluxo `scan`

```text
Arquivo local --[regular, sem symlink, limite de bytes]-->
 SHA-256 do pacote --> parser ZIP/TAR --> validação estrutural/política
                                      | (falha: aborta processamento)
                                      v
                               streaming limitado
                                      |
                          tamanhos, CRC ZIP, hashes
                                      |
                               relatório + código
```

`scan` não altera o backup nem cria uma cópia restaurada. A biblioteca `zipfile` verifica CRC ao consumir o membro até o fim. Para TAR não existe CRC nativo; a leitura completa detecta truncamentos e coleta hashes, mas não autentica dados contra uma fonte de verdade.

## Fluxo `drill`

Executa `scan` integral. Se aprovado, cria uma pasta temporária privada, reabre o arquivo, **não chama** `extractall` nem `extract`; reconstrói os caminhos já validados, grava arquivo por arquivo em modo exclusivo (`xb`), compara o SHA-256 de cada arquivo com o primeiro passe, relê o arquivo gravado e compara novamente. Ao encerrar, o diretório temporário é apagado. Nunca extrai links, dispositivos ou membros especiais.

## Operação em ambientes corporativos

Execute como usuário não privilegiado, dentro de VM/container isolado, com quotas de CPU/tempo/disco e permissões mínimas. Evite montar diretórios do host graváveis pelo operador de inspeção, exceto o diretório temporário confiável. Mantenha mídias originais imutáveis e arquivos de evidência em armazenamento com retenção controlada. O pacote pode ser executado totalmente offline.

## Restrições deliberadas

Não extrai diretórios para local definitivo, não tenta reparar backups, não modifica ACLs nem valida consistência de aplicações. Sem ferramentas de snapshot nativo, aplicações de DR e plano operacional, o resultado prova **somente recuperação dos bytes inspecionados**.
