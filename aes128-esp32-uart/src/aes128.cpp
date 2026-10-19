// Trabalho: AES-128 em dois ESP32, com comunicação pela UART.
// Arquivo: aes128.cpp.
// Autores: Lucas Taveira de Lima e Marcus Viníicius Santos de Almeida.
// Finalidade: implementar as operações do AES-128 sem biblioteca criptográfica.

#include "aes128.h"                                                                                          // Importa as declarações do AES.
#include <string.h>                                                                                          // Fornece memcpy para copiar bytes entre vetores.

static const uint8_t SBOX[256] = {                                                                           // S-box do AES: inverso em GF(2^8) e transformação afim.
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,                                                          // Índices 0x00–0x07.
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,                                                          // Índices 0x08–0x0F.
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,                                                          // Índices 0x10–0x17.
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,                                                          // Índices 0x18–0x1F.
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,                                                          // Índices 0x20–0x27.
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,                                                          // Índices 0x28–0x2F.
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,                                                          // Índices 0x30–0x37.
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,                                                          // Índices 0x38–0x3F.
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,                                                          // Índices 0x40–0x47.
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,                                                          // Índices 0x48–0x4F.
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,                                                          // Índices 0x50–0x57.
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,                                                          // Índices 0x58–0x5F.
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,                                                          // Índices 0x60–0x67.
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,                                                          // Índices 0x68–0x6F.
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,                                                          // Índices 0x70–0x77.
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,                                                          // Índices 0x78–0x7F.
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,                                                          // Índices 0x80–0x87.
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,                                                          // Índices 0x88–0x8F.
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,                                                          // Índices 0x90–0x97.
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,                                                          // Índices 0x98–0x9F.
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,                                                          // Índices 0xA0–0xA7.
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,                                                          // Índices 0xA8–0xAF.
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,                                                          // Índices 0xB0–0xB7.
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,                                                          // Índices 0xB8–0xBF.
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,                                                          // Índices 0xC0–0xC7.
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,                                                          // Índices 0xC8–0xCF.
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,                                                          // Índices 0xD0–0xD7.
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,                                                          // Índices 0xD8–0xDF.
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,                                                          // Índices 0xE0–0xE7.
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,                                                          // Índices 0xE8–0xEF.
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,                                                          // Índices 0xF0–0xF7.
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,                                                          // Índices 0xF8–0xFF.
};

static const uint8_t SBOX_INVERSA[256] = {                                                                   // S-box inversa, usada para descriptografar os bytes.
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,                                                          // Índices 0x00–0x07.
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,                                                          // Índices 0x08–0x0F.
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,                                                          // Índices 0x10–0x17.
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,                                                          // Índices 0x18–0x1F.
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,                                                          // Índices 0x20–0x27.
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,                                                          // Índices 0x28–0x2F.
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,                                                          // Índices 0x30–0x37.
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,                                                          // Índices 0x38–0x3F.
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,                                                          // Índices 0x40–0x47.
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,                                                          // Índices 0x48–0x4F.
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,                                                          // Índices 0x50–0x57.
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,                                                          // Índices 0x58–0x5F.
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,                                                          // Índices 0x60–0x67.
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,                                                          // Índices 0x68–0x6F.
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,                                                          // Índices 0x70–0x77.
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,                                                          // Índices 0x78–0x7F.
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,                                                          // Índices 0x80–0x87.
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,                                                          // Índices 0x88–0x8F.
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,                                                          // Índices 0x90–0x97.
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,                                                          // Índices 0x98–0x9F.
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,                                                          // Índices 0xA0–0xA7.
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,                                                          // Índices 0xA8–0xAF.
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,                                                          // Índices 0xB0–0xB7.
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,                                                          // Índices 0xB8–0xBF.
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,                                                          // Índices 0xC0–0xC7.
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,                                                          // Índices 0xC8–0xCF.
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,                                                          // Índices 0xD0–0xD7.
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,                                                          // Índices 0xD8–0xDF.
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,                                                          // Índices 0xE0–0xE7.
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,                                                          // Índices 0xE8–0xEF.
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,                                                          // Índices 0xF0–0xF7.
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,                                                          // Índices 0xF8–0xFF.
};

static uint8_t xtime(uint8_t valor)                                                                          // Multiplica por x e reduz com o polinômio do AES.
{
    if (valor & 0x80)                                                                                        // Verifica se o produto exige a redução pelo polinômio do AES.
    {
        return (valor << 1) ^ 0x1B;                                                                          // Reduz o resultado se o bit mais alto estiver ativo.
    }

    return valor << 1;                                                                                       // Sem redução, basta deslocar os bits à esquerda.
}

static uint8_t multiplicar(uint8_t multiplicando, uint8_t multiplicador)                                     // Multiplica dois bytes em GF(2^8) usando deslocamentos e XOR.
{
    uint8_t resultado = 0;                                                                                   // Acumula os termos correspondentes aos bits ativos do multiplicador.

    for (int indiceBit = 0; indiceBit < 8; indiceBit++)                                                      // Um byte tem oito bits; cada volta trata um deles.
    {
        if (multiplicador & 1)                                                                               // Verifica se o bit atual do multiplicador contribui para o produto.
        {
            resultado ^= multiplicando;                                                                      // Inclui o multiplicando quando o bit atual do multiplicador é 1.
        }

        multiplicando = xtime(multiplicando);                                                                // Prepara o multiplicando para a próxima potência de x.
        multiplicador >>= 1;                                                                                 // Avança para o próximo bit do multiplicador.
    }

    return resultado;                                                                                        // Devolve o produto calculado.
}

void subBytes(uint8_t estado[16])                                                                            // Substitui os bytes do estado pela tabela S-box.
{
    for (int indiceByte = 0; indiceByte < 16; indiceByte++)                                                  // Percorre os 16 bytes do estado.
    {
        estado[indiceByte] = SBOX[estado[indiceByte]];                                                       // Substitui individualmente os 16 bytes do estado.
    }
}

void invSubBytes(uint8_t estado[16])                                                                         // Restaura os bytes com a tabela S-box inversa.
{
    for (int indiceByte = 0; indiceByte < 16; indiceByte++)                                                  // Percorre os 16 bytes do estado.
    {
        estado[indiceByte] = SBOX_INVERSA[estado[indiceByte]];                                               // Usa a tabela inversa para restaurar cada byte substituído.
    }
}

void shiftRows(uint8_t estado[16])                                                                           // Desloca as linhas do estado para a esquerda.
{
    uint8_t copia[16];                                                                                       // Preserva o estado original.
    memcpy(copia, estado, 16);                                                                               // Copia os bytes antes de mudar suas posições.

    for (int linha = 0; linha < 4; linha++)                                                                  // Cada linha é deslocada para a esquerda pelo número de sua linha.
    {
        for (int coluna = 0; coluna < 4; coluna++)                                                           // Reposiciona cada byte na coluna calculada com aritmética circular.
        {
            estado[linha + 4 * coluna] = copia[linha + 4 * ((coluna + linha) % 4)];                          // Grava o byte na coluna calculada para a esquerda.
        }
    }
}

void invShiftRows(uint8_t estado[16])                                                                        // Desfaz o deslocamento das linhas para a direita.
{
    uint8_t copia[16];                                                                                       // Mantém uma cópia para desfazer os deslocamentos com segurança.
    memcpy(copia, estado, 16);                                                                               // Preserva os bytes antes de reposicioná-los.

    for (int linha = 0; linha < 4; linha++)                                                                  // Percorre cada linha do estado.
    {
        for (int coluna = 0; coluna < 4; coluna++)                                                           // Percorre cada coluna da linha atual.
        {
            estado[linha + 4 * coluna] =                                                                     // Seleciona a posição do byte que será atualizado.
                copia[linha + 4 * ((coluna - linha + 4) % 4)];                                               // Busca o byte correspondente ao deslocamento para a direita.
        }
    }
}

void mixColumns(uint8_t estado[16])                                                                          // Mistura os bytes de cada coluna.
{
    for (int inicioColuna = 0; inicioColuna < 16; inicioColuna += 4)                                         // Processa separadamente as quatro colunas do estado.
    {
        uint8_t byteLinha0 = estado[inicioColuna];                                                           // Preserva o byte da linha 0 da coluna atual.
        uint8_t byteLinha1 = estado[inicioColuna + 1];                                                       // Preserva o byte da linha 1 da coluna atual.
        uint8_t byteLinha2 = estado[inicioColuna + 2];                                                       // Preserva o byte da linha 2 da coluna atual.
        uint8_t byteLinha3 = estado[inicioColuna + 3];                                                       // Preserva o byte da linha 3 da coluna atual.

        estado[inicioColuna] = xtime(byteLinha0) ^ xtime(byteLinha1) ^                                       // Combina as primeiras contribuições para o byte da coluna.
            byteLinha1 ^ byteLinha2 ^ byteLinha3;                                                            // Aplica a primeira linha da matriz do AES.
        estado[inicioColuna + 1] = byteLinha0 ^ xtime(byteLinha1) ^                                          // Combina as primeiras contribuições para o byte da coluna.
            xtime(byteLinha2) ^ byteLinha2 ^ byteLinha3;                                                     // Calcula o segundo byte da coluna misturada.
        estado[inicioColuna + 2] = byteLinha0 ^ byteLinha1 ^                                                 // Combina as primeiras contribuições para o byte da coluna.
            xtime(byteLinha2) ^ xtime(byteLinha3) ^ byteLinha3;                                              // Calcula o terceiro byte da coluna misturada.
        estado[inicioColuna + 3] = xtime(byteLinha0) ^ byteLinha0 ^                                          // Combina as primeiras contribuições para o byte da coluna.
            byteLinha1 ^ byteLinha2 ^ xtime(byteLinha3);                                                     // Calcula o quarto byte da coluna misturada.
    }
}

void invMixColumns(uint8_t estado[16])                                                                       // Desfaz a mistura aplicada às colunas.
{
    for (int inicioColuna = 0; inicioColuna < 16; inicioColuna += 4)                                         // Processa uma coluna por vez.
    {
        uint8_t byteLinha0 = estado[inicioColuna];                                                           // Preserva o byte da linha 0 da coluna atual.
        uint8_t byteLinha1 = estado[inicioColuna + 1];                                                       // Preserva o byte da linha 1 da coluna atual.
        uint8_t byteLinha2 = estado[inicioColuna + 2];                                                       // Preserva o byte da linha 2 da coluna atual.
        uint8_t byteLinha3 = estado[inicioColuna + 3];                                                       // Preserva o byte da linha 3 da coluna atual.

        estado[inicioColuna] =                                                                               // Inicia o cálculo do primeiro byte da coluna.
            multiplicar(byteLinha0, 14) ^ multiplicar(byteLinha1, 11) ^                                      // Combina as contribuições das linhas 0 e 1.
            multiplicar(byteLinha2, 13) ^ multiplicar(byteLinha3, 9);                                        // Calcula o primeiro byte com a matriz inversa.

        estado[inicioColuna + 1] =                                                                           // Inicia o cálculo do segundo byte da coluna.
            multiplicar(byteLinha0, 9) ^ multiplicar(byteLinha1, 14) ^                                       // Combina as contribuições das linhas 0 e 1.
            multiplicar(byteLinha2, 11) ^ multiplicar(byteLinha3, 13);                                       // Calcula o segundo byte com a matriz inversa.

        estado[inicioColuna + 2] =                                                                           // Inicia o cálculo do terceiro byte da coluna.
            multiplicar(byteLinha0, 13) ^ multiplicar(byteLinha1, 9) ^                                       // Combina as contribuições das linhas 0 e 1.
            multiplicar(byteLinha2, 14) ^ multiplicar(byteLinha3, 11);                                       // Calcula o terceiro byte com a matriz inversa.

        estado[inicioColuna + 3] =                                                                           // Inicia o cálculo do quarto byte da coluna.
            multiplicar(byteLinha0, 11) ^ multiplicar(byteLinha1, 13) ^                                      // Combina as contribuições das linhas 0 e 1.
            multiplicar(byteLinha2, 9) ^ multiplicar(byteLinha3, 14);                                        // Calcula o quarto byte com a matriz inversa.
    }
}

void addRoundKey(uint8_t estado[16], const uint8_t chave[16])                                                // Combina o estado com uma chave de rodada.
{
    for (int indiceByte = 0; indiceByte < 16; indiceByte++)                                                  // Percorre os 16 bytes do estado.
    {
        estado[indiceByte] ^= chave[indiceByte];                                                             // Aplica XOR com a chave de rodada.
    }
}

void expandirChave(const uint8_t chave[16], uint8_t chaves[176])                                             // Gera as onze chaves usadas nas rodadas do AES-128.
{
    memcpy(chaves, chave, 16);                                                                               // Copia a chave original para a rodada inicial.
    uint8_t rcon = 1;                                                                                        // A constante de rodada começa em 1 e avança por xtime.

    for (int posicao = 16; posicao < 176; posicao += 4)                                                      // Gera as palavras restantes, quatro bytes de cada vez.
    {
        uint8_t palavra[4];                                                                                  // Começa com a palavra de quatro bytes gerada anteriormente.
        memcpy(palavra, chaves + posicao - 4, 4);                                                            // Copia a palavra anterior para iniciar a próxima.

        if (posicao % 16 == 0)                                                                               // A cada 16 bytes, aplica a transformação da chave.
        {
            uint8_t primeiro = palavra[0];                                                                   // Guarda o primeiro byte antes de girar a palavra.

            palavra[0] = SBOX[palavra[1]] ^ rcon;                                                            // Substitui e combina o primeiro byte com rcon.
            palavra[1] = SBOX[palavra[2]];                                                                   // Substitui o segundo byte da palavra.
            palavra[2] = SBOX[palavra[3]];                                                                   // Substitui o terceiro byte da palavra.
            palavra[3] = SBOX[primeiro];                                                                     // Substitui o último byte usando o valor guardado.

            rcon = xtime(rcon);                                                                              // Calcula a constante para a rodada seguinte.
        }

        for (int indiceByte = 0; indiceByte < 4; indiceByte++)                                               // Combina a palavra atual com a palavra anterior.
        {
            chaves[posicao + indiceByte] =                                                                   // Seleciona o byte da nova palavra da chave.
                chaves[posicao - 16 + indiceByte] ^ palavra[indiceByte];                                     // Combina bytes para formar a nova palavra da chave.
        }
    }
}

void criptografarBloco(uint8_t bloco[16], const uint8_t chaves[176], uint8_t estados[5][16])                 // Cifra um bloco e registra os estados da primeira rodada, se solicitado.
{
    addRoundKey(bloco, chaves);                                                                              // Combina o bloco com a chave inicial antes das dez rodadas.

    if (estados != 0)                                                                                        // Verifica se foi solicitado o registro do estado inicial.
    {
        memcpy(estados[0], bloco, 16);                                                                       // Registra o estado inicial, se solicitado.
    }

    for (int rodada = 1; rodada <= 10; rodada++)                                                             // Executa as dez rodadas de cifração.
    {
        subBytes(bloco);                                                                                     // Substitui os bytes usando a S-box.

        if (rodada == 1 && estados != 0)                                                                     // Verifica se esta etapa da primeira rodada deve ser registrada.
        {
            memcpy(estados[1], bloco, 16);                                                                   // Guarda o resultado de SubBytes na primeira rodada.
        }

        shiftRows(bloco);                                                                                    // Desloca as linhas do estado.

        if (rodada == 1 && estados != 0)                                                                     // Verifica se esta etapa da primeira rodada deve ser registrada.
        {
            memcpy(estados[2], bloco, 16);                                                                   // Guarda o resultado de ShiftRows na primeira rodada.
        }

        if (rodada != 10)                                                                                    // Verifica se a rodada ainda precisa misturar as colunas.
        {
            mixColumns(bloco);                                                                               // Mistura as colunas, exceto na última rodada, como define o AES.
        }

        if (rodada == 1 && estados != 0)                                                                     // Verifica se esta etapa da primeira rodada deve ser registrada.
        {
            memcpy(estados[3], bloco, 16);                                                                   // Guarda o resultado de MixColumns na primeira rodada.
        }

        addRoundKey(bloco, chaves + 16 * rodada);                                                            // Aplica a chave desta rodada.

        if (rodada == 1 && estados != 0)                                                                     // Verifica se esta etapa da primeira rodada deve ser registrada.
        {
            memcpy(estados[4], bloco, 16);                                                                   // Guarda o resultado de AddRoundKey na primeira rodada.
        }
    }
}

void descriptografarBloco(uint8_t bloco[16], const uint8_t chaves[176])                                      // Decifra um bloco de 16 bytes com AES-128.
{
    addRoundKey(bloco, chaves + 160);                                                                        // A decifração começa pela última chave de rodada.

    for (int rodada = 9; rodada >= 0; rodada--)                                                              // Percorre as rodadas em ordem inversa até a chave original.
    {
        invShiftRows(bloco);                                                                                 // Desfaz ShiftRows e, em seguida, SubBytes.

        invSubBytes(bloco);                                                                                  // Desfaz a substituição dos bytes.

        addRoundKey(bloco, chaves + 16 * rodada);                                                            // Aplica a chave da rodada atual.

        if (rodada != 0)                                                                                     // Verifica se ainda falta desfazer a mistura das colunas.
        {
            invMixColumns(bloco);                                                                            // Pula a mistura na rodada final.
        }
    }
}

int contarBitsDiferentes(const uint8_t *primeiroVetor, const uint8_t *segundoVetor, int tamanho)             // Conta os bits diferentes entre dois vetores de bytes.
{
    int total = 0;                                                                                           // Soma quantos bits diferem nos dois vetores.

    for (int indiceByte = 0; indiceByte < tamanho; indiceByte++)                                             // Compara primeiro cada par de bytes.
    {
        uint8_t diferenca = primeiroVetor[indiceByte] ^ segundoVetor[indiceByte];                            // XOR produz 1 nas posições em que os bits são diferentes.

        for (int bit = 0; bit < 8; bit++)                                                                    // Conta os oito bits do resultado do XOR.
        {
            total += diferenca & 1;                                                                          // Soma o bit menos significativo à contagem.
            diferenca >>= 1;                                                                                 // Avança para o próximo bit da diferença.
        }
    }

    return total;                                                                                            // Devolve o total de bits diferentes.
}
