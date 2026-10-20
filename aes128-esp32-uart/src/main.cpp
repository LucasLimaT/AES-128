// Trabalho: AES-128 em dois ESP32, com comunicação pela UART.
// Arquivo: main.cpp.
// Autores: Lucas Taveira de Lima e Marcus Viníicius Santos de Almeida.
// Finalidade: transmitir dados criptografados, recuperar as mensagens e controlar o LED da placa B.

#include <Arduino.h>                                                                                         // Declara as funções básicas do Arduino.
#include <string.h>                                                                                          // Declara as funções de cópia e comparação de memória.
#include "aes128.h"                                                                                          // Declara as funções do AES usadas neste arquivo.
#include "protocol.h"                                                                                        // Declara o protocolo e o estado do receptor.

const char MATRICULA_A[] = "2021278440073";                                                                  // Matrícula de Lucas Taveira de Lima.
const char MATRICULA_B[] = "2021278440278";                                                                  // Matrícula de Marcus Viníicius Santos de Almeida.
const bool TRANSMISSOR = true;                                                                               // Use true na placa A e false na placa B.

const char COMANDO_LIGAR[] = "LIGAR LED VERDE.";                                                             // Texto de 16 bytes que solicita o acionamento do LED verde.
const char COMANDO_DESLIGAR[] = "DESLIGAR LED    ";                                                          // Texto de 16 bytes, incluindo quatro espaços após LED.

const int PINO_RX = 16;                                                                                      // RX recebe o TX da outra placa; conecte também os pinos GND.
const int PINO_TX = 17;                                                                                      // TX transmite para o RX da outra placa.
const int PINO_LED_VERDE = 2;                                                                                // Saída usada para o Led verde;
const unsigned long INTERVALO_ENVIO_MS = 5000;                                                               // Intervalo entre o envio das matrículas e de cada comando.

uint8_t chave[16];                                                                                           // Guarda a chave de 16 bytes formada com as duas matrículas.
uint8_t chaves[176];                                                                                         // Guarda as 11 chaves de rodada geradas pelo AES.
uint8_t mensagem[MAX_DADOS];                                                                                 // Guarda a mensagem original e seu preenchimento PKCS#7.
uint8_t criptografado[MAX_DADOS];                                                                            // Guarda os blocos já criptografados e prontos para transmissão.
int tamanhoCriptografado = 0;                                                                                // Registra o tamanho, em bytes, do texto criptografado.

Receptor receptor;                                                                                           // Mantém o estado atual da recepção na placa B.

bool pronto = false;                                                                                         // Indica se a inicialização foi concluída.
unsigned long ultimoEnvio = 0;                                                                               // Guarda a hora do último envio periódico.
int proximoEnvio = 0;                                                                                        // 0: matrículas; 1: ligar; 2: desligar; 3: ligar novamente.

void imprimirHex(const char *titulo, const uint8_t *dados, int tamanho)                                      // Mostra uma sequência de bytes em hexadecimal no monitor serial.
{
    const char digitos[] = "0123456789abcdef";                                                               // Tabela de caracteres usada para escrever cada byte em hexadecimal.

    Serial.print(titulo);                                                                                    // Escreve o rótulo antes dos valores.

    for (int indiceByte = 0; indiceByte < tamanho; indiceByte++)                                             // Converte cada byte em dois algarismos hexadecimais.
    {
        Serial.print(digitos[dados[indiceByte] >> 4]);                                                       // Escreve o primeiro algarismo hexadecimal do byte.
        Serial.print(digitos[dados[indiceByte] & 15]);                                                       // Escreve o segundo algarismo hexadecimal do byte.
    }

    Serial.println();                                                                                        // Termina a linha depois de imprimir todos os bytes.
}

bool conferirVetor(const uint8_t chaveTeste[16], const uint8_t claro[16], const uint8_t esperado[16])        // Confere a criptografia e a descriptografia de um vetor oficial do FIPS-197.
{
    uint8_t chavesTeste[176], bloco[16];                                                                     // Reserva espaço para as chaves de rodada e para uma cópia do bloco.

    expandirChave(chaveTeste, chavesTeste);                                                                  // Expande a chave de teste para as 11 rodadas.
    memcpy(bloco, claro, 16);                                                                                // Copia o texto claro para que o vetor recebido não seja alterado.

    criptografarBloco(bloco, chavesTeste);                                                                   // Cifra o bloco de teste.

    if (memcmp(bloco, esperado, 16) != 0)                                                                    // Compara o bloco criptografado com o resultado oficial.
    {
        return false;                                                                                        // Falha se o resultado criptografado não corresponder ao vetor oficial.
    }

    descriptografarBloco(bloco, chavesTeste);                                                                // Descriptografa o resultado para conferir também as operações inversas.
    return memcmp(bloco, claro, 16) == 0;                                                                    // O resultado deve voltar a ser igual ao texto claro inicial.
}

bool validarAES()                                                                                            // Valida a implementação com os vetores indicados no enunciado.
{
    const uint8_t chaveB[16] = {                                                                             // Vetor do Apêndice B do FIPS-197.
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,                                                      // Bytes 0 a 7 da chave de teste.
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c                                                       // Bytes 8 a 15 da chave de teste.
    };

    const uint8_t claroB[16] = {                                                                             // Texto claro do vetor do Apêndice B.
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,                                                      // Bytes 0 a 7 do texto claro.
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34                                                       // Bytes 8 a 15 do texto claro.
    };

    const uint8_t esperadoB[16] = {                                                                          // Resultado criptografado esperado no Apêndice B.
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,                                                      // Bytes 0 a 7 do resultado esperado.
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32                                                       // Bytes 8 a 15 do resultado esperado.
    };

    const uint8_t chaveC[16] = {                                                                             // Chave e texto claro do Apêndice C.1 do FIPS-197.
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15                                                 // Bytes sequenciais de 0 a 15.
    };

    const uint8_t claroC[16] = {                                                                             // Texto claro do vetor do Apêndice C.1.
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,                                                      // Bytes 0 a 7 do texto claro.
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff                                                       // Bytes 8 a 15 do texto claro.
    };

    const uint8_t esperadoC[16] = {                                                                          // Resultado criptografado esperado no Apêndice C.1.
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,                                                      // Bytes 0 a 7 do resultado esperado.
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a                                                       // Bytes 8 a 15 do resultado esperado.
    };

    bool passouB = conferirVetor(chaveB, claroB, esperadoB);                                                 // Confere criptografia e descriptografia para os dois vetores oficiais.
    bool passouC = conferirVetor(chaveC, claroC, esperadoC);                                                 // Confere o segundo vetor oficial.

    Serial.print("FIPS B: ");                                                                                // Mostra no monitor o resultado de cada conferência.

    if (passouB)                                                                                             // Verifica se o vetor oficial foi aprovado.
    {
        Serial.println("OK");                                                                                // Informa que a criptografia e a descriptografia estão corretas.
    } else {                                                                                                 // Trata a falha na conferência do vetor.
        Serial.println("FALHOU");                                                                            // Informa que o resultado não corresponde ao vetor oficial.
    }

    Serial.print("FIPS C.1: ");                                                                              // Identifica o resultado do vetor C.1.

    if (passouC)                                                                                             // Verifica se o vetor oficial foi aprovado.
    {
        Serial.println("OK");                                                                                // Informa que a criptografia e a descriptografia estão corretas.
    } else {                                                                                                 // Trata a falha na conferência do vetor.
        Serial.println("FALHOU");                                                                            // Informa que o resultado não corresponde ao vetor oficial.
    }

    return passouB && passouC;                                                                               // Continua somente se ambos passarem.
}

bool prepararMensagem()                                                                                      // Prepara a mensagem e demonstra as etapas do AES, a avalanche e o ECB.
{
    int tamanho = formarMensagem(MATRICULA_A, MATRICULA_B, mensagem, MAX_DADOS);                             // Formata o texto com as duas matrículas.
    tamanhoCriptografado = adicionarPadding(mensagem, tamanho, MAX_DADOS);                                   // Acrescenta o padding exigido para completar blocos de 16 bytes.

    if (tamanhoCriptografado < 0)                                                                            // Verifica se houve falha ao preparar o preenchimento.
    {
        return false;                                                                                        // Interrompe se a mensagem não couber no vetor.
    }

    imprimirHex("Chave ASCII em hexadecimal: ", chave, 16);                                                  // Exibe os 16 bytes da chave da dupla.
    imprimirHex("Mensagem com PKCS#7: ", mensagem, tamanhoCriptografado);                                    // Exibe o texto preparado para criptografia.

    imprimirHex("Chave da rodada 0: ", chaves, 16);                                                          // Exibe a chave usada antes da primeira rodada.
    imprimirHex("Chave da rodada 1: ", chaves + 16, 16);                                                     // Exibe a chave usada na primeira rodada.

    uint8_t estados[5][16];                                                                                  // Reserva espaço para as cinco etapas da primeira rodada.
    memcpy(criptografado, mensagem, tamanhoCriptografado);                                                   // Copia os dados para o vetor criptografado.

    criptografarBloco(criptografado, chaves, estados);                                                       // Cifra o primeiro bloco e guarda os estados.

    for (int inicioBloco = 16; inicioBloco < tamanhoCriptografado; inicioBloco += 16)                        // Percorre os blocos após o primeiro.
    {
        criptografarBloco(criptografado + inicioBloco, chaves);                                              // Cifra os demais blocos de forma independente no modo ECB.
    }

    imprimirHex("Bloco 1 - AddRoundKey inicial: ", estados[0], 16);                                          // Mostra o estado após a chave inicial.
    imprimirHex("Bloco 1 - SubBytes: ", estados[1], 16);                                                     // Mostra o estado após SubBytes.
    imprimirHex("Bloco 1 - ShiftRows: ", estados[2], 16);                                                    // Mostra o estado após ShiftRows.
    imprimirHex("Bloco 1 - MixColumns: ", estados[3], 16);                                                   // Mostra o estado após MixColumns.
    imprimirHex("Bloco 1 - AddRoundKey da rodada 1: ", estados[4], 16);                                      // Mostra o estado após a chave da rodada 1.

    imprimirHex("Criptografado final: ", criptografado, tamanhoCriptografado);                               // Exibe toda a mensagem criptografada.

    uint8_t chaveAlterada[16], chavesAlteradas[176], bloco[16];                                              // Inicia a demonstração de avalanche e reserva os vetores necessários.
    memcpy(chaveAlterada, chave, 16);                                                                        // Mantém intacta a chave usada na mensagem original.
    chaveAlterada[0] ^= 1;                                                                                   // Inverte somente o bit menos significativo do primeiro byte.

    expandirChave(chaveAlterada, chavesAlteradas);                                                           // Expande a chave que contém o bit invertido.
    imprimirHex("Chave com 1 bit invertido: ", chaveAlterada, 16);                                           // Mostra a chave alterada.

    int diferentes = 0;                                                                                      // Soma os bits diferentes em todos os blocos da mensagem.

    for (int inicioBloco = 0; inicioBloco < tamanhoCriptografado; inicioBloco += 16)                         // Percorre os blocos criptografados da mensagem.
    {
        memcpy(bloco, mensagem + inicioBloco, 16);                                                           // Copia o bloco claro sem modificar a mensagem original.
        criptografarBloco(bloco, chavesAlteradas);                                                           // Cifra a cópia com a chave alterada.

        diferentes += contarBitsDiferentes(criptografado + inicioBloco, bloco, 16);                          // Conta as diferenças em relação ao bloco criptografado original.
        imprimirHex("Bloco criptografado com a chave alterada: ", bloco, 16);                                // Mostra o resultado produzido pela chave alterada.
    }

    Serial.print("Avalanche: ");                                                                             // Exibe a contagem e o percentual de bits diferentes.
    Serial.print(diferentes);                                                                                // Mostra a quantidade de bits diferentes.
    Serial.print(" de ");                                                                                    // Separa a contagem do total de bits.
    Serial.print(tamanhoCriptografado * 8);                                                                  // Mostra o total de bits comparados.
    Serial.print(" bits mudaram (");                                                                         // Inicia a apresentação do percentual.
    Serial.print(100.0 * diferentes / (tamanhoCriptografado * 8), 2);                                        // Calcula e mostra o percentual de diferenças.
    Serial.println("%). Espera-se uma mudança de cerca de 50% dos bits, mas essa proporção pode variar.");   // Mostra o percentual de diferenças e explica a variação esperada.

    const uint8_t chaveExemplo[16] = {                                                                       // Inicia a demonstração de ECB com a chave fictícia do PDF.
        '2', '0', '2', '3', '1', '0', '0', '1',                                                              // Oito primeiros caracteres da chave fictícia.
        '2', '0', '2', '3', '1', '0', '0', '2'                                                               // Oito últimos caracteres da chave fictícia.
    };
    uint8_t blocos[48], chavesExemplo[176];                                                                  // Reserva três blocos de dados e as chaves de rodada do exemplo.

    expandirChave(chaveExemplo, chavesExemplo);                                                              // Gera as chaves de rodada do exemplo ECB.
    memcpy(blocos, COMANDO_LIGAR, 16);                                                                       // Preenche o primeiro bloco com o comando de ligar.
    memcpy(blocos + 16, COMANDO_DESLIGAR, 16);                                                               // Preenche o segundo bloco com o comando de desligar.
    memcpy(blocos + 32, COMANDO_LIGAR, 16);                                                                  // Repete o primeiro comando no terceiro bloco.

    for (int inicioBloco = 0; inicioBloco < 48; inicioBloco += 16)                                           // Percorre os três blocos do exemplo ECB.
    {
        criptografarBloco(blocos + inicioBloco, chavesExemplo);                                              // Cifra separadamente cada bloco completo.
    }

    imprimirHex("ECB, bloco 1: ", blocos, 16);                                                               // Exibe os bytes criptografados do primeiro bloco.
    imprimirHex("ECB, bloco 2: ", blocos + 16, 16);                                                          // Exibe os bytes criptografados do segundo bloco.
    imprimirHex("ECB, bloco 3: ", blocos + 32, 16);                                                          // Exibe os bytes criptografados do terceiro bloco.

    Serial.println("O modo ECB revela repetições: blocos claros iguais geram blocos criptografados iguais.");// Explica que blocos claros iguais revelam repetições no modo ECB.
    Serial.println("O modo ECB não autentica os dados: um invasor pode trocar ou repetir blocos.");          // Explica que o modo ECB não impede a troca ou a repetição de blocos.
    Serial.println("Na prática, use CBC com um IV novo e imprevisível, CTR sem repetir o nonce/contador ");  // Apresenta os cuidados com o IV de CBC e o nonce/contador de CTR.
    Serial.println("ou GCM, que também autentica os dados. Nunca reutilize o nonce com a mesma chave.");     // Apresenta a autenticação de GCM e a regra de não reutilizar o nonce.

    return true;                                                                                             // Informa que a mensagem foi preparada.
}

void enviarMensagem()                                                                                        // Envia o quadro binário definido no enunciado pela UART2.
{
    int tamanhoEnvio = tamanhoCriptografado;                                                                 // Começa com o tamanho da mensagem das matrículas, incluindo PKCS#7.

    if (proximoEnvio == 0)                                                                                   // Seleciona a mensagem original da dupla no início de cada ciclo.
    {
        memcpy(criptografado, mensagem, tamanhoCriptografado);                                               // Recupera a mensagem preparada para que ela possa ser criptografada novamente.
        Serial.println("Enviando as matrículas da dupla.");                                                  // Identifica a mensagem de dados que será transmitida.
    } else {
        if (proximoEnvio == 2)                                                                               // O segundo comando do ciclo deve apagar o LED da placa B.
        {
            memcpy(criptografado, COMANDO_DESLIGAR, 16);                                                     // Copia exatamente os 16 bytes do comando, sem o terminador da string.
            Serial.println("Enviando o comando para desligar o LED verde.");                                 // Identifica o comando selecionado.
        } else {
            memcpy(criptografado, COMANDO_LIGAR, 16);                                                        // Usa o mesmo comando de ligar no primeiro e no terceiro envios de comando.
            Serial.println("Enviando o comando para ligar o LED verde.");                                    // Identifica o comando selecionado.
        }

        tamanhoEnvio = adicionarPadding(criptografado, 16, MAX_DADOS);                                       // Acrescenta um bloco PKCS#7 completo ao comando de 16 bytes.
    }

    if (tamanhoEnvio < 0)                                                                                    // Confere se o preenchimento do comando coube no vetor.
    {
        Serial.println("O comando excede o limite do protocolo.");                                           // Informa a falha sem transmitir um quadro incompleto.
        return;                                                                                              // Mantém a etapa atual para que o ciclo não avance em caso de erro.
    }

    for (int inicioBloco = 0; inicioBloco < tamanhoEnvio; inicioBloco += 16)                                 // Percorre os blocos da mensagem selecionada.
    {
        criptografarBloco(criptografado + inicioBloco, chaves);                                              // Criptografa cada bloco com a chave da dupla usada também na placa B.
    }

    imprimirHex("Criptografado do quadro enviado: ", criptografado, tamanhoEnvio);                           // Permite comparar os quadros que transportam comandos repetidos.

    Serial2.write(MARCADOR);                                                                                 // Escreve o marcador de início do quadro.
    Serial2.write((uint8_t)(tamanhoEnvio / 16));                                                             // Informa a quantidade de blocos da mensagem selecionada.
    Serial2.write(criptografado, tamanhoEnvio);                                                              // Envia o quadro em bytes brutos, incluindo o preenchimento criptografado.

    Serial.println("Quadro enviado pela UART2.");                                                            // Confirma o envio no monitor serial.
    proximoEnvio = (proximoEnvio + 1) % 4;                                                                   // Avança na sequência e retorna às matrículas após o terceiro comando.
}

void receberMensagem()                                                                                       // Lê, descriptografia e mostra os quadros que chegam pela UART2.
{
    if (verificarTempoLimite(receptor, millis()))                                                            // Descarta e informa um quadro parcial cujo tempo limite expirou.
    {
        Serial.println("Tempo limite: quadro incompleto descartado.");                                       // Informa que o quadro parcial foi descartado.
    }

    while (Serial2.available() > 0)                                                                          // Processa os bytes que já chegaram pela UART2.
    {
        if (verificarTempoLimite(receptor, millis()))                                                        // Verifica o prazo antes de processar cada byte recebido.
        {
            Serial.println("Tempo limite: quadro incompleto descartado.");                                   // Informa que o prazo expirou durante a recepção.
        }

        int resultado = receberByte(receptor, (uint8_t)Serial2.read(), millis());                            // Entrega o próximo byte ao controle de etapas do protocolo.

        if (resultado == -1)                                                                                 // Verifica se o protocolo recusou a quantidade de blocos.
        {
            Serial.println("Quadro inválido: a quantidade de blocos não pode ser zero.");                    // Informa que a quantidade de blocos do quadro deve ser maior que zero.
        }

        if (resultado == 1)                                                                                  // Continua quando todos os bytes do quadro chegaram.
        {
            imprimirHex("Criptografado recebido: ", receptor.dados, receptor.tamanho);                       // Exibe o quadro completo antes de decifrá-lo.

            for (int inicioBloco = 0; inicioBloco < receptor.tamanho;                                        // Percorre os blocos criptografados recebidos pela UART.
                 inicioBloco += 16)                                                                          // Avança um bloco de 16 bytes a cada repetição.
            {
                descriptografarBloco(receptor.dados + inicioBloco, chaves);                                  // Descriptografa o bloco atual recebido.
            }

            int tamanho = removerPadding(receptor.dados, receptor.tamanho);                                  // Confere o padding e obtém o tamanho do texto original.

            if (tamanho < 0)                                                                                 // Verifica se o preenchimento terminou corretamente.
            {
                Serial.println("Preenchimento PKCS#7 inválido: confira as chaves e a transmissão.");         // Informa a falha no PKCS#7 e orienta a conferência das chaves e da transmissão.
            } else {                                                                                         // Exibe o texto quando o preenchimento é válido.
                Serial.print("Texto original: ");                                                            // write respeita o tamanho e dispensa um '\0' no final do vetor.
                Serial.write(receptor.dados, tamanho);                                                       // Mostra o texto sem exigir um byte terminador.
                Serial.println();                                                                            // Pula para a próxima linha do monitor.

                if (tamanho == 16 && memcmp(receptor.dados, COMANDO_LIGAR, 16) == 0)                         // Aceita somente o comando completo de ligar, depois de validar o PKCS#7.
                {
                    digitalWrite(PINO_LED_VERDE, HIGH);                                                      // Acende o LED ligado ao pino configurado da placa B.
                    Serial.println("LED verde ligado.");                                                     // Confirma a execução do comando recebido.
                } else if (tamanho == 16 && memcmp(receptor.dados, COMANDO_DESLIGAR, 16) == 0)               // Aceita somente o comando completo de desligar, com os quatro espaços finais.
                {
                    digitalWrite(PINO_LED_VERDE, LOW);                                                       // Apaga o LED da placa B.
                    Serial.println("LED verde desligado.");                                                  // Confirma a execução do comando recebido.
                }
            }
        }                                                                                                    // ECB não autentica os dados recebidos.
    }
}

void setup()                                                                                                 // Inicializa e configura a placa.
{
    Serial.begin(115200);                                                                                    // Inicia a porta serial usada pelo monitor do computador.

    if (!TRANSMISSOR)                                                                                        // Apenas a placa receptora controla o LED físico.
    {
        pinMode(PINO_LED_VERDE, OUTPUT);                                                                     // Configura o pino escolhido como saída digital.
        digitalWrite(PINO_LED_VERDE, LOW);                                                                   // Mantém o LED desligado durante a inicialização e as validações.
    }

    Serial2.setRxBufferSize(MAX_DADOS + 2);                                                                  // Reserva espaço para o maior quadro permitido pelo protocolo.
    Serial2.begin(115200, SERIAL_8N1, PINO_RX, PINO_TX);                                                     // Inicia a UART2 nos pinos configurados.

    delay(1500);                                                                                             // Aguarda a inicialização das portas seriais.

    reiniciarRecepcao(receptor);                                                                             // Zera o estado de recepção antes de começar.

    if (!validarAES())                                                                                       // Interrompe a configuração se algum vetor oficial falhar.
    {
        Serial.println("Execução interrompida: falha na validação do AES.");                                 // Informa que os vetores oficiais falharam.
        return;                                                                                              // Interrompe a inicialização da placa.
    }

    if (!formarChave(MATRICULA_A, MATRICULA_B, chave))                                                       // Forma a chave da dupla a partir das matrículas configuradas.
    {
        Serial.println("Use matrículas não vazias que contenham apenas dígitos.");                           // Explica o formato esperado para as matrículas.
        return;                                                                                              // Interrompe a inicialização da placa.
    }

    expandirChave(chave, chaves);                                                                            // Prepara as chaves de rodada usadas na criptografia e na descriptografia.

    if (TRANSMISSOR)                                                                                         // Escolhe o comportamento definido para esta placa.
    {
        if (!prepararMensagem())                                                                             // Confere se a mensagem cabe no quadro.
        {
            Serial.println("A mensagem excede o limite do protocolo.");                                      // Informa que a mensagem é grande demais.
            return;                                                                                          // Interrompe a inicialização sem enviar dados.
        }

        enviarMensagem();                                                                                    // A placa A prepara e envia o primeiro quadro.
        ultimoEnvio = millis();                                                                              // Salva o instante para controlar os próximos envios.
    } else {                                                                                                 // Configura esta placa para receber mensagens.
        Serial.println("Receptor pronto. Aguardando um quadro pela UART2.");                                 // Informa que a placa está aguardando dados.
    }

    pronto = true;                                                                                           // Libera a execução periódica da tarefa.
}

void loop()                                                                                                  // Repete a tarefa correspondente ao papel desta placa.
{
    if (!pronto)                                                                                             // Aguarda se a inicialização ou a validação não foram concluídas.
    {
        delay(100);                                                                                          // Aguarda antes de tentar novamente.
        return;                                                                                              // Não executa a tarefa antes da inicialização.
    }

    if (TRANSMISSOR)                                                                                         // Verifica se esta placa deve transmitir.
    {
        if (millis() - ultimoEnvio >= INTERVALO_ENVIO_MS)                                                    // Verifica se chegou a hora de reenviar.
        {
            enviarMensagem();                                                                                // Envia a próxima mensagem da sequência de matrículas e comandos.
            ultimoEnvio = millis();                                                                          // Atualiza o instante do último envio.
        }
    } else {                                                                                                 // Na placa receptora, processa os dados disponíveis.
        receberMensagem();                                                                                   // Na placa B, verifica se chegaram bytes para processar.
    }

    delay(1);                                                                                                // Libera um curto intervalo para as demais tarefas.
}
