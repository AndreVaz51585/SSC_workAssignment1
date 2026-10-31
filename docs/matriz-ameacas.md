# Matriz de ameaças: executar e interpretar

O canal protegido é proxy ↔ stream server. Consideramos um atacante capaz de
observar, alterar, repetir, remover ou trocar a ordem dos registos da ligação,
sem conhecer os segredos configurados e sem controlar os processos das pontas.
Autenticação por PSK prova posse do segredo partilhado, não a identidade de uma pessoa.

## Representação para o relatório

Cada linha liga uma capacidade do atacante a uma alteração concreta e a uma
condição verificável. A rejeição tem de ocorrer antes de aceitar uma sessão ou
entregar conteúdo adulterado, conforme a fase.

| ID | Ameaça | Alteração no teste | Resultado esperado | Propriedade verificada |
| --- | --- | --- | --- | --- |
| A1 | Impersonação sem a PSK correta | Um participante usa outra PSK do mesmo tamanho | Autenticação do ClientHello falha; sem sessão estabelecida; alerta Type 255 no cenário testado | Posse do segredo de autenticação |
| A2 | Alteração do handshake | Inverter um bit no Type 1 ou alterar prefixo/ciphertext/tag do Type 2/3 | Mensagem rejeitada; o servidor não aceita um handshake adulterado | Integridade e ligação das mensagens ao handshake |
| A3 | Alteração do vídeo/metadados | Inverter um bit num DATA protegido ou na sua tag; alterar metadados | Falha de autenticação; nenhum byte adulterado é encaminhado | Integridade e autenticidade dos registos |
| A4 | Replay | Repetir um DATA; reutilizar Type 2/3 de outra sessão | Registo repetido rejeitado; resposta antiga não conclui uma sessão nova | Ordem, frescura e contexto de sessão |
| A5 | Remoção ou reordenação | Remover um DATA ou trocar dois DATA | Sequência inesperada; transferência abortada | Deteção de lacunas e ordem |
| A6 | Truncamento | Remover/adulterar END ou terminar antes da mensagem completa | Transferência incompleta, sem término autenticado bem-sucedido | Completude autenticada |
| A7 | Entrada malformada | Declarar payload excessivo, cabeçalho incompleto ou tipo desconhecido | Erro de parsing/limite; payload excessivo não é alocado/lido como válido | Validação do enquadramento e limites |
| A8 | Escuta passiva | Inspecionar saída cifrada para plaintext conhecido; verificar vetores e nonces | Saída compatível com os vetores; conteúdo não transmitido como plaintext nesse canal; nonces/contadores separados | Evidência de implementação da confidencialidade; não uma prova formal |

A alteração de uma proposta sem recalcular a tag testa autenticação. Uma proposta
com tag válida mas proibida pela política local testa compatibilidade. São testes
diferentes. O teste `authenticated but incompatible proposal` conhece a chave de
TESTE para produzir uma tag válida: representa um peer autenticado com proposta
incompatível, não um atacante externo que adivinhou a PSK.

## Como os ataques são representados no código

A classe dedicada `adversarialTest` usa o apoio `ProtocolTestSupport.FrameFilter`, um
OutputStream que acumula o registo serializado e, no flush, aplica uma alteração
antes de o entregar ao socket. O recetor recebe os bytes adulterados e executa o
código normal. Este filtro pertence apenas aos testes, não ao código de produção.

- Alteração: `byte XOR 1` num byte escolhido.
- Replay: enviar o mesmo registo duas vezes.
- Remoção: devolver um array vazio para esse registo.
- Reordenação: guardar um registo e entregar o seguinte primeiro.
- Truncamento: suprimir END ou cortar os bytes disponíveis.

Manipulamos registos de aplicação, não pacotes IP: TCP normalmente reconstitui
perdas e reordenação de pacotes. O objetivo é verificar o protocolo acima de TCP.
Não é preciso uma ferramenta externa de ataque nem alterar o código de produção.

## Começar por A1, passo a passo

Abre `src/test/kotlin/ssc/adversarial/adversarialTest.kt` e executa pelo botão de teste
do IntelliJ o método `test A1a attacker with guessed secrets cannot authenticate as proxy`.
O mesmo caso pode ser executado na raiz do projeto com JDK 21:

```sh
./gradlew test --tests 'ssc.adversarial.adversarialTest.test A1a*' --console=plain
```

O teste:

1. Carrega uma configuração pública de TESTE para o servidor.
2. Dá ao atacante segredos candidatos diferentes, com tamanhos válidos; os restantes parâmetros são iguais.
3. Chama `exchangeHandshake`, que cria sockets locais e executa ProxyHandshake e ServerHandshake.
4. Recolhe o resultado de ambos e os tipos de resposta.
5. Exige falha de autenticação do ClientHello no servidor, falha no atacante e Type 255.

Este caso percorre cinco perfis. A1b isola o MacKey incorreto no CTR. A2b substitui
a chave pública por uma DH válida do atacante, preservando a tag antiga. O caso
C0 confirma que uma transferência sem ataque funciona para os mesmos perfis.

Um teste verde significa que a tentativa foi rejeitada como esperado. Não significa
que a ligação do atacante funcionou. Se a sessão indevida fosse aceite, os asserts
falhariam. Não precisas de editar os teus XML reais nem arrancar Docker para este caso.

## Executar os restantes grupos

No IntelliJ podes executar cada método individualmente e inspecionar os asserts.
No terminal, a classe inteira é a demonstração principal:

```sh
./gradlew test --tests 'ssc.adversarial.adversarialTest' --console=plain
```

Os grupos técnicos complementares continuam disponíveis:

```sh
# Handshake autorizado e validação da política local
./gradlew test --tests 'ssc.handshake.handshakeTest' --console=plain

# Registos, ordem, truncamento e contexto de sessão
./gradlew test --tests 'ssc.secureStream.secureStreamTest' --console=plain

# Funcionamento HTTP, ranges, paths e concorrência
./gradlew test --tests 'ssc.secureHttp.secureHttpTest' --console=plain

# Validação do enquadramento binário
./gradlew test --tests 'ssc.protocolMessageCodec.protocolMessageCodecTest' --console=plain

# Primitivas, tags, AAD, IV e separação de contadores
./gradlew test --tests 'ssc.aeadCipher.aeadCipherTest' --tests 'ssc.messageProtection.messageProtectionTest' --console=plain
```

Na classe dedicada, A3/A4a/A5/A6 são métodos separados, com uma alteração visível
em cada método. Cada um percorre os cinco perfis. Os casos DATA/END enviam
metadados válidos antes do ataque e exigem corpo HTTP incompleto com apenas um
prefixo correto do original. A3c testa separadamente a falha dos metadados antes
dos headers HTTP. O número de métodos JUnit não é o total de combinações com perfis.

Se os metadados já originaram HTTP 200/206, uma falha posterior fecha a resposta;
não se envia um segundo status 502 a meio do vídeo. Se a autenticação dos primeiros
metadados falhar, pode ser enviada uma resposta 502 antes de começar o corpo.
O critério é não entregar dados adulterados nem concluir uma transferência inválida,
não obter sempre o mesmo status HTTP em todas as fases.

Depois de testes isolados, executa a suite completa para guardar um relatório global:

```sh
./gradlew test --console=plain
```

Consulta `build/reports/tests/test/index.html`, ou XML em `build/test-results/test/`.
Um teste filtrado produz um relatório desse subconjunto; o relatório de uma execução
completa deve ser usado quando quiseres apresentar a totalidade da suite.

## Testes manuais complementares

- Três browsers em simultâneo: funcionalidade e independência de clientes, já
  confirmadas pelo autor em [validacao-manual.md](validacao-manual.md).
- Vídeo recebido com SHA-256 igual ao original: correção de uma transferência.
- Configurações incompatíveis: rejeição segundo a política configurada; para
  isolar PSK/proposta, preferir os testes Kotlin que controlam uma variável de cada vez.

Abrir janelas não demonstra resistência a falsificação/replay. Comparar hashes
numa transferência normal também não substitui testar mensagens adulteradas.

## Limites que devem constar do relatório

- Browser ↔ proxy continua em HTTP. Uma captura desse lado pode mostrar o vídeo;
  a confidencialidade aqui foi concebida para proxy ↔ server.
- Um atacante pode cortar a ligação. Detetamos a transferência incompleta;
  não garantimos disponibilidade perante bloqueio de tráfego.
- Blocos anteriores válidos podem já ter sido entregues quando um ataque é detetado.
  A garantia é não entregar bytes do registo inválido nem aceitar um fim inválido.
- Repetir Type 1 pode originar nova resposta do servidor; não afirmamos que todo
  ClientHello repetido é imediatamente rejeitado. A captura antiga não deve permitir
  concluir uma sessão fresca. Os testes existentes cobrem replay de Type 2/3 e DATA.
- Vetores/testes de ciphertext não provam segurança formal; a análise depende das
  primitivas, da autenticação do DH, dos nonces, da derivação e da gestão de segredos.
- Resistência a um MITM é um argumento do desenho apoiado pelos testes de alteração,
  autenticação e replay. Não afirmamos ter implementado/executado um MITM completo.

O inventário técnico com os nomes exatos de métodos está em [threat-model.md](threat-model.md).
