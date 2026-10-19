// Trabalho: AES-128 em dois ESP32, com comunicação pela UART.
// Arquivo: protocol.h.
// Autores: Lucas Taveira de Lima e Marcus Viníicius Santos de Almeida.
// Finalidade: declarar as funções de preparação da mensagem e recepção do quadro.

#ifndef PROTOCOL_H                                                                                           // Evita incluir este arquivo mais de uma vez.
#define PROTOCOL_H                                                                                           // Define a proteção do cabeçalho.

#include <stdint.h>                                                                                          // Define tipos de inteiros com tamanho fixo.

const uint8_t MARCADOR = 0xAA;                                                                               // O quadro começa com o byte fixo 0xAA.
const int MAX_DADOS = 255 * 16;                                                                              // O campo de quantidade permite até 255 blocos de 16 bytes.
const uint32_t TEMPO_LIMITE_MS = 1000;                                                                       // Prazo para receber o quadro completo.

bool formarChave(const char *matriculaA, const char *matriculaB, uint8_t chave[16]);                         // Usa os 8 últimos dígitos de A e B; completa com zeros à esquerda.
int formarMensagem(const char *matriculaA, const char *matriculaB, uint8_t *dados, int capacidade);          // Monta a mensagem com as duas matrículas e retorna seu tamanho.
int adicionarPadding(uint8_t *dados, int tamanho, int capacidade);                                           // Acrescenta o preenchimento PKCS#7 e retorna o novo tamanho.
int removerPadding(const uint8_t *dados, int tamanho);                                                       // Confere e remove o PKCS#7; retorna -1 se inválido.

struct Receptor                                                                                              // Guarda o andamento da recepção e os bytes do quadro atual.
{
    int etapa;                                                                                               // 0: marcador; 1: quantidade; 2: dados criptografados.
    int tamanho;                                                                                             // Quantidade total de bytes criptografados esperada.
    int recebidos;                                                                                           // Quantidade de bytes criptografados já recebida.

    uint32_t inicio;                                                                                         // Instante em que o marcador foi recebido.

    uint8_t dados[MAX_DADOS];                                                                                // Espaço reservado para os blocos do quadro.
};

void reiniciarRecepcao(Receptor &receptor);                                                                  // Prepara o receptor para aguardar um novo marcador.
bool verificarTempoLimite(Receptor &receptor, uint32_t agora);                                               // Descarta a recepção se o tempo limite tiver expirado.
int receberByte(Receptor &receptor, uint8_t valor, uint32_t agora);                                          // Avança a recepção e informa se o quadro está pronto.

#endif                                                                                                       // Encerra a proteção contra inclusão repetida.
