# Verificação dos requisitos e plano do relatório

Revisão de 31/10/2026. Fontes: enunciado, secções 1.2–6; FAQ, secções 2.2,
4.3, 4.5, 4.6, 4.7 e 4.9. A indicação posterior do professor, comunicada pelo autor,
permite submeter o link do repositório público. As FAQ fornecidas ainda descrevem
um ZIP; essa diferença deve seguir a indicação atual recebida pelo autor.

## Requisitos e estado

| Requisito | Implementação/evidência | O que falta fechar |
| --- | --- | --- |
| Compreender a referência e partir da arquitetura Proxy–Server | Código Java preservado; baseline Kotlin e análise das funções de sockets/HTTP | Descrever o ponto de partida; não afirmar uma execução Java original que não esteja registada |
| Secure Proxy e Secure Stream Server | SecureProxyServer e SecureStreamServer | Publicar a versão atual no repositório |
| Transmitir MP4 reproduzível no browser | Seleção de ficheiros, catálogo, HTTP/Range e transmissão protegida; reprodução validada | Identificar os vídeos e o perfil usados nos resultados |
| Autenticar as pontas e estabelecer um canal dinâmico | PSK, Type 1 autenticado, Type 2 protegido e confirmação Type 3; novas chaves por ligação | Explicar que se autentica posse dos segredos, não utilizadores humanos |
| Acordo DH autenticado | ffdhe2048 com chaves efémeras, autenticação e ligação ao transcript | Explicar a proteção contra substituição DH/MITM e as suas hipóteses |
| Negociar uma configuração compatível | Proposta autenticada, comparação com a política local e confirmação exata | Descrever proposta/aceitação; não apresentar como negociação de listas |
| Configuração externa para os dois peers | XML por papel e perfil; validação estrutural e semântica | Confirmar preparação dos ficheiros num clone limpo |
| Alterar algoritmos/parâmetros sem recompilar | Catálogo de construções suportadas; seleção pelo XML | Explicitar que combinações fora do catálogo são rejeitadas |
| Header version/release/type/length | 1:1, 2+2+1+4 bytes, big endian | O tamanho de 4 bytes para length é uma decisão do projeto |
| Type 1: sequência e PCC | Campos públicos com sequência/proposta, acrescidos de random, DH e HMAC | Declarar extensões e codificação binária em vez da string ilustrativa |
| Type 2: SEQY, SRV e CCC protegidos | Sequência +1, desafio de 256 bits, confirmação e pública DH; prefixo serverRandom | Explicar por que a proteção inicial depende dos segredos provisionados |
| Type 3: SEQZ, R e MEDIA protegidos | Sequência +2, SHA-256(SRV), nome do ficheiro e Range opcional | Explicar a chave derivada com DH e o pedido de início do stream |
| Type 4: sequência e bloco cifrado | Sequências consecutivas; metadados primeiro, depois DATA; tag e contexto autenticado | Documentar subtipo/metadados como extensão |
| Type 5: sequência e ENDBLOCK | END com sequência interior e string aleatória; autenticação; validação do tamanho total | Descrever retenção do último bloco até END |
| Type 255 para violações do handshake | Alerta e aborto nos coordenadores; testes A1/A2 | Alertas anteriores à sessão não justificam aceitar/fazer downgrade |
| Confidencialidade do stream | AES-GCM, ChaCha20-Poly1305 ou AES-CTR/HMAC | Delimitar proxy ↔ servidor; browser ↔ proxy continua HTTP |
| Integridade, autenticidade e resistência a falsificação | Tags AEAD ou Encrypt-then-MAC; verificação antes de usar conteúdo | Explicar os dados abrangidos por AAD/MAC |
| Replay, ordem, duplicação, lacunas e truncamento | Sequência/contexto/END e limites; casos A4–A6 | Apresentar as rejeições observadas |
| Gestão de chaves, IVs/nonces/tags | HKDF por fase/direção; nonces AEAD únicos; domínios de contador CTR separados | Distinguir PSK, segredo DH, segredo intermédio e chaves de tráfego |
| Várias configurações | Nove pares XML; testes funcionais e construções distintas | Tabela curta de perfis e indicação dos efetivamente medidos |
| Modelo de ameaças explícito | Matriz A1–A7; hipóteses/limites em threat-model.md | Incluir uma tabela ameaça → mecanismo → evidência no relatório |
| Compromisso de sessão e forward secrecy | DH novo e derivações separadas; análise descrita abaixo | É obrigatório explicar consequências; testes de round-trip não provam esta propriedade |
| Métricas exigidas no proxy | DATA autenticados, escritas concluídas, bytes, duração e throughput | Selecionar observações completas e explicar método/diferenças de volume |
| Testes funcionais e adversariais | 22 métodos dedicados; 141 métodos na suite completa na última execução | Guardar relatório Gradle e descrever o que cada grupo verifica |
| Concorrência/Step 5 | Servidor e proxy usam pools; autor confirmou três browsers em simultâneo | Distinguir clientes de instâncias do proxy; o README inclui um segundo processo proxy |
| Execução em hosts distintos | Endereço configurável e instruções em secure-browser.md | Não afirmar teste entre dois computadores se não for realizado |
| Docker com configuração externa | Uma imagem; dois serviços; XML/media em mounts só de leitura | Verificação final a partir de cópia limpa |
| README suficiente para avaliar | Reorganizado por preparação, arranque, perfis, testes e resultados esperados | Confirmar os passos com a versão que for efetivamente publicada |
| Relatório PDF, 4–6 páginas, formato de artigo | Ainda por preparar | Texto, resultados, referências e revisão do PDF |
| Submissão por repositório público | Acesso público confirmado | Código atual ainda tem muitos ficheiros não versionados; falta integrar e publicar a versão final |

Não existe requisito de implementar Authentication Server, login humano, certificados
ou TLS nesta parte. O Authentication Server pertence ao WA2. As opções RC6/CBC/etc.
do exemplo não constituem uma obrigação de implementar todos os algoritmos possíveis.

## Decisões a declarar sem as apresentar como formato literal do professor

A implementação segue os tipos, a sequência e as funções do protocolo de referência,
com campos adicionais necessários ao desenho autenticado: DH públicas, randoms, tags,
contextos de transcript, Range e metadados. PCC/CCC são codificadas em campos binários
com comprimentos explícitos, em vez de uma única string ALG/MODE/IV/Padding.
O relatório deve mostrar o formato real e justificar estas escolhas. Não escrever
que o formato é byte a byte idêntico ao exemplo do enunciado.

O parser corrige também erros sintáticos do XML ilustrativo e acrescenta Handshake
para os parâmetros/limites suportados. IV=NULL significa gestão dinâmica em runtime.

## Compromisso de chaves: análise a incluir

- Material de tráfego completo comprometido: a confidencialidade/autenticidade da
  direção e sessão correspondentes deixa de estar garantida. Em CTR há chaves
  distintas de cifra e MAC; conhecer apenas uma não equivale a conhecer ambas.
- A derivação por rótulo/direção e os DH frescos separam sessões; uma chave de
  tráfego não é a PSK nem deve permitir calcular as chaves de outras sessões.
- Compromisso posterior dos segredos de autenticação suficientes (SKey nos perfis
  AEAD; SKey e MacKey nos perfis CTR): permite recuperar a proteção bootstrap das
  mensagens gravadas, mas não fornece por si só o segredo DH. A proteção das
  sessões passadas depende de DH continuar seguro e de não reter as privadas efémeras.
- A exposição desses segredos permite futuras tentativas de impersonação; não se
  promete recuperação automática após compromisso. No CTR, conhecer apenas SKey
  não fornece a raiz de autenticação enquanto MacKey continuar desconhecido.
- Eliminação em memória JVM é best effort. Não afirmar uma prova formal de forward
  secrecy a partir de testes que apenas confirmam chaves diferentes.

## Estrutura proposta: artigo de até seis páginas

Sem capa ou índice autónomos. Título, autores, afiliação NOVA, resumo curto e
palavras-chave no início. Planear seis páginas incluindo referências, salvo outra
indicação do professor.

1. **Introdução.** Objetivo, baseline e âmbito WA1. Um ou dois parágrafos.
2. **Arquitetura e modelo de ameaças.** Responsabilidades, ligação protegida e
   hipóteses. Um esquema simples; distinguir autenticação por PSK de login humano.
3. **Protocolo e estabelecimento de chaves.** Types 1–5/255, campos reais, DH
   autenticado, desafio/resposta, PSK/bootstrap, derivação por fase/direção,
   proteção dos registos e terminação. Esta é a maior secção.
4. **Configuração e implementação.** Tabela das construções, tamanhos, regras XML,
   ausência de padding, IV dinâmico, AEAD versus EtM e integração com HTTP/Range.
   Referir componentes por responsabilidade; não listar todos os DTOs.
5. **Validação e análise de segurança.** Reprodução, perfis, hashes, concorrência,
   tabela de ameaças, testes/rejeições, métricas e metodologia. Incluir compromisso
   de chaves e forward secrecy. Separar resultados observados de argumentos do desenho.
6. **Conclusão.** O que foi obtido e limites concretos, incluindo disponibilidade,
   HTTP até ao browser e provisioning externo. Referências no fim.

Distribuição indicativa: título/resumo/introdução 0,5 página; arquitetura/ameaças 0,75;
protocolo/chaves 1,5; configuração 0,75; validação/análise 1,5; conclusão/referências 1.
Ajustar ao template sem aumentar o total com páginas decorativas.

## Estilo e referências

Descrever o mecanismo aplicado e a razão da escolha. Exemplo: «O proxy verifica a
sequência e a tag antes de encaminhar o bloco. Um registo repetido é rejeitado por
não corresponder à sequência esperada.» Evitar afirmações como «solução totalmente
segura», «garantia absoluta» ou «arquitetura inovadora».

Usar os slides para conceitos/notação: cifra simétrica, hash, MAC, AEAD, DH e
separação/frescura de chaves. Para os parâmetros exatos da API/construção, usar as
referências do código, por exemplo RFC 5869 para HKDF e RFC 7919 para ffdhe2048.
Não copiar um tamanho genérico de uma transparência para descrever outro perfil:
os valores do relatório devem coincidir com os XML e com a implementação.

## LaTeX e preparação dos resultados

Recomendação: adaptar o template LaTeX já conhecido pelo autor, mudando identificação,
afiliação e metadados para a NOVA. Usar um formato de artigo com título compacto.
A exigência é PDF; Word/LibreOffice também são válidos, mas não justificam uma
mudança de ferramenta se o template existente já funciona.

Antes de fechar o texto, escolher poucas transferências completas, usando o mesmo
ficheiro/perfil por comparação. Registar tamanho original, DATA autenticados e
encaminhados, bytes do protocolo, duração e MB/s. Não usar cancelamentos/Range como
se fossem um download integral; não inventar médias, desvios ou ensaios que não foram
realizados. Os resultados automáticos anteriores arquivados em build não devem ser
apresentados como observações manuais do autor.
