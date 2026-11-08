# Contribuição

Obrigado pelo interesse no RestoreGate. O projeto aceita melhorias de ergonomia, políticas, confiabilidade e cobertura de testes.

## Fluxo recomendado

1. Verifique as issues e evite duplicação de trabalho.
2. Crie uma branch por mudança e PR com motivação, escopo e impacto no modelo de ameaças.
3. Acrescente testes que reproduzam o comportamento proposto, incluindo casos negativos.
4. Rode `python -m compileall -q src tests` e `python -m unittest discover -s tests -v` antes de abrir o PR.
5. Mantenha compatibilidade com Python 3.10+, biblioteca padrão e execução offline.
6. Atualize README, THREAT_MODEL e CHANGELOG quando houver mudanças de comportamento.

Não suba backups reais, senhas, tokens, endpoints privados nem arquivos maliciosos prontos para distribuição. Gere casos de teste sintéticos em memória. Vulnerabilidades devem seguir `SECURITY.md`, não issues abertas.

Padrão de commits: `feat:`, `fix:`, `test:`, `docs:`, `ci:`; versões seguem Semantic Versioning. Licença MIT.
