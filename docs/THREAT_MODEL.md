# Modelo de ameaças — RestoreGate v0.1.0

## Ativos

- Máquina onde o RestoreGate executa: espaço em disco, memória e caminhos locais.
- Disponibilidade operacional do pipeline de verificação.
- Integridade e confidencialidade dos dados de backup e dos relatórios.

## Atacante considerado

Um agente pode fornecer um arquivo ZIP/TAR malformado ou manipulado e escolher nomes e tamanhos dos membros. O atacante **não** controla o processo Python, seu sistema operacional, a biblioteca padrão, a política local ou a árvore do diretório temporário. Ataques a essas premissas são limites explícitos do escopo.

## Defesas implementadas

| Ameaça | Controle | Risco residual |
| --- | --- | --- |
| Zip Slip / traversal | Rejeita nomes absolutos, `..`, `.` e componentes vazios | Bugs do interpretador/sistema de arquivos fora do modelo |
| Ambiguidade de caminhos Windows/Unicode | Rejeita `\\`, `:`, nomes reservados, NFC incorreto, colisões casefold | Sistemas de arquivos com normalizações não contempladas |
| Symlink, hardlink, dispositivos | Recusa tipos especiais ZIP/TAR | Corrida de arquivos se diretório temporário confiável for adulterado externamente |
| Zip bomb / exaustão de recursos | Limites de volume, arquivo, quantidade de entradas, tamanho do pacote, razão ZIP; leitura de 64 KiB | Tempo de CPU, memória do parser/central directory ZIP, TAR compactado, expansão de metadados; use sandbox externo |
| Pacote aparentemente válido mas corrompido | Leitura integral e CRC do ZIP; hashes de dois passes + releitura em disco | Integridade contra um backup previamente adulterado não é comprovada |
| Falha na restauração | Ensaio controlado em diretório temporário, escrita exclusiva e comparação de hashes | Teste não inclui permissões, sistema de banco, boot, aplicação ou disponibilidade de rede |
| Backup fora do prazo | Política opcional `max_age_hours` | `mtime` não autenticado; fonte pode ser falsificada |
| Evidência sensível | Saídas opcionais e somente locais | Caminhos e dados operacionais podem expor informações ao copiar relatórios |

## Não objetivos

Antivírus, sanitização de anexos, criptografia, validação de assinaturas externas, integridade contra host comprometido, RTO/RPO, varredura de redes, integração nativa com provedores de backup, parsing de imagens de máquina virtual e execução de scripts de restore.

## Política de falha

Adota postura **fail-closed** no processamento dos payloads: um erro estrutural interrompe a leitura de arquivos e impede o ensaio. Validação da política é anterior à leitura do arquivo. Um membro com tipo perigoso impede o processo. Códigos de erro são comunicados no stdout/JSON e o exit code não é zero.

## Segurança do próprio projeto

Sem telemetria, rede, envio de arquivos nem dependências de execução. CI com permissões apenas de leitura e actions fixadas em SHA. Testes adversariais são feitos com arquivos sintéticos para evitar exposição de dados sensíveis.
