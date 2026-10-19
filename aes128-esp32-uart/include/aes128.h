// Trabalho: AES-128 em dois ESP32, com comunicação pela UART.
// Arquivo: aes128.h.
// Autores: Lucas Taveira de Lima e Marcus Viníicius Santos de Almeida.
// Finalidade: declarar as funções de cifração, decifração e expansão da chave.

#ifndef AES128_H                                                                                             // Evita incluir este arquivo mais de uma vez.
#define AES128_H                                                                                             // Define a proteção do cabeçalho.

#include <stdint.h>                                                                                          // Fornece o tipo uint8_t, usado para representar bytes.

void expandirChave(const uint8_t chave[16], uint8_t chaves[176]);                                            // Gera as 11 chaves de rodada do AES-128.

void subBytes(uint8_t estado[16]);                                                                           // Substitui cada byte do estado usando a tabela S-box do AES.
void invSubBytes(uint8_t estado[16]);                                                                        // Desfaz SubBytes usando a tabela inversa.

void shiftRows(uint8_t estado[16]);                                                                          // Desloca as linhas do estado para a esquerda.
void invShiftRows(uint8_t estado[16]);                                                                       // Desloca as linhas do estado para a direita e desfaz ShiftRows.

void mixColumns(uint8_t estado[16]);                                                                         // Mistura os bytes de cada coluna para difundir os valores.
void invMixColumns(uint8_t estado[16]);                                                                      // Desfaz a mistura das colunas durante a decifração.

void addRoundKey(uint8_t estado[16], const uint8_t chave[16]);                                               // Combina o estado com uma chave de rodada por meio de XOR.

void criptografarBloco(uint8_t bloco[16], const uint8_t chaves[176], uint8_t estados[5][16] = 0);            // Cifra um bloco e permite registrar os cinco estados da primeira rodada.
void descriptografarBloco(uint8_t bloco[16], const uint8_t chaves[176]);                                     // Decifra o bloco com as chaves expandidas.

int contarBitsDiferentes(const uint8_t *primeiroVetor, const uint8_t *segundoVetor, int tamanho);            // Conta os bits diferentes entre dois vetores de bytes.

#endif                                                                                                       // Encerra a proteção contra inclusão repetida.
