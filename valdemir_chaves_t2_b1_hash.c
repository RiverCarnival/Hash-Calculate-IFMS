#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define Tamanho_bytes 1048576

void opcao1()
{
    char *arquivo_entrada = malloc(1000 * sizeof(char));
    printf("Digite o nome do arquivo que deseja calcular o hash: ");
    scanf("%s", arquivo_entrada);

    char *arquivo_saida = "Valdemir_Chaves_t2_b1_hash.sha512";

    FILE *entrada = fopen(arquivo_entrada, "rb");
    if (!entrada) 
    {
        printf("Erro ao abrir o arquivo de entrada.\n");
        return;
    }

    FILE *saida = fopen(arquivo_saida, "wb");
    if (!saida) 
    {
        printf("Erro ao abrir o arquivo de saída.\n\n");
        return;
    }

    unsigned char chunk[Tamanho_bytes];
    size_t bytes_lidos;
    SHA512_CTX contexto;
    SHA512_Init(&contexto);

    while ((bytes_lidos = fread(chunk, 1, Tamanho_bytes, entrada)) > 0) 
    {
        unsigned char output[SHA512_DIGEST_LENGTH];
        SHA512(chunk, bytes_lidos, output);

        for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) 
        {
            fprintf(saida, "%02x", output[i]);
        }
        fprintf(saida, "\n");
    
        printf("\n Numero de bytes lidos por parte: %d\n", bytes_lidos);
    }


    rewind(entrada);
    SHA512_CTX contexto_completo;
    SHA512_Init(&contexto_completo);
    while ((bytes_lidos = fread(chunk, 1, Tamanho_bytes, entrada)) > 0) 
    {
        SHA512_Update(&contexto_completo, chunk, bytes_lidos);

        printf("\n Numero de Total de bytes lidos: %d\n", bytes_lidos);
    }
    unsigned char output_completo[SHA512_DIGEST_LENGTH];
    
    SHA512_Final(output_completo, &contexto_completo);

    fprintf(saida, "Hash do arquivo:\n");
    for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) 
    {
        fprintf(saida, "%02x", output_completo[i]);
    }
    fprintf(saida, "\n");

    printf("\n Numero de bytes lidos: %d\n", bytes_lidos);

    fclose(entrada);
    fclose(saida);
    free(arquivo_entrada);
}

void opcao2()
{
    char *arquivo_entrada = "valdemir_chaves_t2_b1_hash.input";
    
    char *arquivo_saida = "Valdemir_Chaves_t2_b1_hash.sha512";

    FILE *entrada = fopen(arquivo_entrada, "rb");
    if (!entrada) 
    {
        printf("Erro ao abrir o arquivo de entrada.\n");
        return;
    }

    FILE *saida = fopen(arquivo_saida, "wb");
    if (!saida) 
    {
        printf("Erro ao abrir o arquivo de saída.\n");
        return;
    }

    unsigned char chunk[Tamanho_bytes];
    size_t bytes_lidos;
    SHA512_CTX contexto;
    SHA512_Init(&contexto);

    while ((bytes_lidos = fread(chunk, 1, Tamanho_bytes, entrada)) > 0) 
    {
        unsigned char output[SHA512_DIGEST_LENGTH];
        SHA512(chunk, bytes_lidos, output);

        for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) 
        {
            fprintf(saida, "%02x", output[i]);
        }
        fprintf(saida, "\n");
        printf("\n Numero de bytes lidos: %d\n", bytes_lidos);
    }

    rewind(entrada);
    SHA512_CTX contexto_completo;
    SHA512_Init(&contexto_completo);
    while ((bytes_lidos = fread(chunk, 1, Tamanho_bytes, entrada)) > 0) 
    {
        SHA512_Update(&contexto_completo, chunk, bytes_lidos);
    
        printf("\n Numero de Total de bytes lidos: %d\n", bytes_lidos);
    }
    unsigned char output_completo[SHA512_DIGEST_LENGTH];
    SHA512_Final(output_completo, &contexto_completo);

    fprintf(saida, "Hash do arquivo:\n");
    for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) 
    {
        fprintf(saida, "%02x", output_completo[i]);
    }
    fprintf(saida, "\n");

    fclose(entrada);
    fclose(saida);
    free(arquivo_entrada);
}


int main() {
    
    int opcao;

    printf("\nDigite 1 para calcular o hash de um arquivo selecionado.\n");
    printf("\nDigite 2 para calcular o hash DO ARQUIVO FORNECIDO PELO PROGRAMA!.\n");
    printf("\nDigite um valor diferente de 1 e 2 para sair.\n");

    scanf("%d", &opcao);

    if(opcao == 1)
    {
        printf("\nCalculando o hash do arquivo selecionado...\n");
        printf("\nCertifique-se de que o arquivo esteja na mesma pasta do executavel do programa.\n");
        opcao1();
    }
    else if(opcao == 2)
    {
        printf("\nCalculando o hash do arquivo fornecido pelo programa...\n");
        opcao2();
    }
    else
    {
        return 0;
    }

    return 0;
}