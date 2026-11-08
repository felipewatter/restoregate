# Changelog

Adota a estrutura do [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e versionamento semântico.

## [Unreleased]

Sem alterações pendentes planejadas para a versão inicial.

## [0.1.0] — pré-publicação

### Adicionado

- CLI Python offline com modos `scan` e `drill` para arquivos ZIP e TAR.
- Proteções contra caminhos inseguros, tipos especiais, colisões de nomes, profundidade e estouro de limites de recursos.
- Consumo integral, validação de CRC ZIP, SHA-256 do pacote e releitura após restauração temporária.
- Política JSON estrita, caminho obrigatório, idade máxima por mtime, mínimo de arquivos.
- Evidências JSON e SARIF, códigos de saída para automação, documentação bilíngue.
- Suíte de testes unitários/adversariais e workflow multiplataforma em 12 combinações.

**Observação:** publicação e release dependem de aprovação e do CI remoto concluído com sucesso.
