// Trabalho: AES-128 em dois ESP32, com comunicação pela UART.
// Arquivo: protocol.cpp.
// Autores: Lucas Taveira de Lima e Marcus Viníicius Santos de Almeida.
// Finalidade: montar a chave e a mensagem e processar os quadros recebidos.

#include "protocol.h"                                                                                        // Importa as declarações do protocolo.
#include <string.h>                                                                                          // Fornece strlen para medir as matrículas.

bool formarChave(const char *matriculaA, const char *matriculaB, uint8_t chave[16])                          // Usa os últimos oito dígitos de cada matrícula.
{
    const char *matriculas[2] = {matriculaA, matriculaB};                                                    // Guarda as matrículas na ordem da chave.

    for (int aluno = 0; aluno < 2; aluno++)                                                                  // Processa primeiro a matrícula A e depois a matrícula B.
    {
        int tamanho = strlen(matriculas[aluno]);                                                             // Mede quantos caracteres há na matrícula atual.

        for (int indiceCaractere = 0; indiceCaractere < 8; indiceCaractere++)                                // Reserva oito posições da chave para cada matrícula.
        {
            int origem = tamanho - 8 + indiceCaractere;                                                      // Localiza um dos oito últimos caracteres.

            if (origem < 0)                                                                                  // Verifica se faltam caracteres para completar oito posições.
            {
                chave[aluno * 8 + indiceCaractere] = '0';                                                    // Completa a posição com o caractere ASCII zero.
            } else {                                                                                         // Usa um dos últimos caracteres da matrícula.
                chave[aluno * 8 + indiceCaractere] = matriculas[aluno][origem];                              // Copia o caractere para a chave.
            }
        }
    }

    return true;                                                                                             // A chave contém oito caracteres de cada matrícula.
}

int formarMensagem(const char *matriculaA, const char *matriculaB, uint8_t *dados, int capacidade)           // Monta a mensagem com as duas matrículas e retorna seu tamanho.
{
    int tamanhoA = strlen(matriculaA);                                                                       // Mede separadamente os comprimentos das matrículas.
    int tamanhoB = strlen(matriculaB);                                                                       // Mede quantos caracteres há na matrícula B.

    int tamanho = tamanhoA + tamanhoB + 5;                                                                   // Os cinco caracteres adicionais são "A:;B:".

    if (tamanho > capacidade)                                                                                // Verifica se a mensagem ultrapassa a capacidade do vetor.
    {
        return -1;                                                                                           // Não escreve a mensagem se o vetor recebido for pequeno demais.
    }

    int posicao = 0;                                                                                         // A variável posicao indica o próximo espaço livre no vetor.
    dados[posicao++] = 'A';                                                                                  // Escreve o prefixo e os dois pontos do campo A.
    dados[posicao++] = ':';                                                                                  // Completa o prefixo do campo A.

    for (int indiceCaractere = 0; indiceCaractere < tamanhoA; indiceCaractere++)                             // Percorre os caracteres da matrícula A.
    {
        dados[posicao++] = matriculaA[indiceCaractere];                                                      // Copia os caracteres da primeira matrícula.
    }

    dados[posicao++] = ';';                                                                                  // Separa os campos e começa o campo B.
    dados[posicao++] = 'B';                                                                                  // Escreve o prefixo do campo B.
    dados[posicao++] = ':';                                                                                  // Completa o prefixo do campo B.

    for (int indiceCaractere = 0; indiceCaractere < tamanhoB; indiceCaractere++)                             // Percorre os caracteres da matrícula B.
    {
        dados[posicao++] = matriculaB[indiceCaractere];                                                      // Copia os caracteres da segunda matrícula.
    }

    return tamanho;                                                                                          // Retorna a quantidade de bytes escritos.
}

int adicionarPadding(uint8_t *dados, int tamanho, int capacidade)                                            // Acrescenta bytes PKCS#7 para que o tamanho seja múltiplo de 16.
{
    if (tamanho < 0 || tamanho > capacidade)                                                                 // Identifica um tamanho fora dos limites do vetor.
    {
        return -1;                                                                                           // Rejeita tamanhos fora dos limites do vetor.
    }

    int quantidade = 16 - tamanho % 16;                                                                      // O padding tem de 1 a 16 bytes.

    if (quantidade > capacidade - tamanho)                                                                   // Verifica se o preenchimento cabe no espaço restante.
    {
        return -1;                                                                                           // Informa que o vetor não tem espaço para o preenchimento.
    }

    for (int indiceByte = 0; indiceByte < quantidade; indiceByte++)                                          // Percorre os bytes que receberão o preenchimento.
    {
        dados[tamanho + indiceByte] = quantidade;                                                            // Repete o tamanho do padding em cada byte.
    }

    return tamanho + quantidade;                                                                             // Retorna o tamanho após o preenchimento.
}

int removerPadding(const uint8_t *dados, int tamanho)                                                        // Confere e remove o padding PKCS#7.
{
    if (tamanho <= 0 || tamanho % 16 != 0)                                                                   // Identifica tamanhos sem blocos completos de 16 bytes.
    {
        return -1;                                                                                           // O texto precisa conter pelo menos um bloco completo.
    }

    int quantidade = dados[tamanho - 1];                                                                     // O último byte informa o número de bytes de preenchimento.

    if (quantidade < 1 || quantidade > 16)                                                                   // Identifica uma quantidade de preenchimento inválida.
    {
        return -1;                                                                                           // Esse número deve estar entre 1 e 16.
    }

    for (int indiceByte = tamanho - quantidade; indiceByte < tamanho; indiceByte++)                          // Todos os bytes finais devem conter o mesmo valor.
    {
        if (dados[indiceByte] != quantidade)                                                                 // Confere o valor de cada byte do preenchimento.
        {
            return -1;                                                                                       // Rejeita o preenchimento se um byte for diferente.
        }
    }

    return tamanho - quantidade;                                                                             // Retorna o tamanho dos dados depois de remover o preenchimento.
}

void reiniciarRecepcao(Receptor &receptor)                                                                   // Prepara o receptor para outro quadro.
{
    receptor.etapa = 0;                                                                                      // Volta à etapa que aguarda o marcador 0xAA.
    receptor.tamanho = 0;                                                                                    // Limpa o tamanho esperado do quadro anterior.
    receptor.recebidos = 0;                                                                                  // Limpa a contagem de bytes já recebidos.
    receptor.inicio = 0;                                                                                     // Limpa o instante inicial usado para verificar o tempo limite.
}

bool verificarTempoLimite(Receptor &receptor, uint32_t agora)                                                // Descarta a recepção quando o prazo termina.
{
    if (receptor.etapa != 0 && agora - receptor.inicio >= TEMPO_LIMITE_MS)                                   // A subtração lida com a volta de millis() a zero.
    {
        reiniciarRecepcao(receptor);                                                                         // Abandona os dados parciais e volta a procurar o marcador.
        return true;                                                                                         // Informa ao chamador que o prazo expirou.
    }

    return false;                                                                                            // O prazo ainda não expirou ou a recepção ainda não começou.
}

int receberByte(Receptor &receptor, uint8_t valor, uint32_t agora)                                           // Processa um byte do quadro recebido.
{
    if (receptor.etapa == 0)                                                                                 // Na etapa zero, procura o byte fixo que marca o início do quadro.
    {
        if (valor == MARCADOR)                                                                               // Inicia a recepção ao encontrar o marcador.
        {
            reiniciarRecepcao(receptor);                                                                     // Prepara o estado do receptor e registra a hora de início.
            receptor.inicio = agora;                                                                         // Guarda o instante para controlar o prazo.
            receptor.etapa = 1;                                                                              // O próximo byte informa a quantidade de blocos.
        }
    } else if (receptor.etapa == 1)                                                                          // Na etapa um, lê a quantidade de blocos criptografados.
    {
        if (valor == 0)                                                                                      // O quadro precisa ter pelo menos um bloco.
        {
            reiniciarRecepcao(receptor);                                                                     // Um quadro sem blocos não é válido.
            return -1;                                                                                       // Informa que o tamanho anunciado é inválido.
        }

        receptor.tamanho = 16 * valor;                                                                       // Cada bloco AES contém 16 bytes.
        receptor.etapa = 2;                                                                                  // O receptor passa a guardar os bytes criptografados.
    } else {                                                                                                 // A etapa final recebe o conteúdo criptografado.
        receptor.dados[receptor.recebidos++] = valor;                                                        // Na carga, 0xAA é dado comum; guarda o byte recebido.

        if (receptor.recebidos == receptor.tamanho)                                                          // Confere se todos os bytes anunciados chegaram.
        {
            receptor.etapa = 0;                                                                              // A quantidade esperada chegou; o chamador pode descriptografar o quadro.
            return 1;                                                                                        // Informa que o quadro completo está pronto.
        }
    }

    return 0;                                                                                                // Ainda não chegaram todos os bytes do quadro.
}
