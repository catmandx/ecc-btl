#include "mbedtls/config.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <string.h>

char *SERVER_NAME =  "localhost";
char *SERVER_PORT = "11999";

int init(mbedtls_net_context *network_server,
         mbedtls_ecdh_context *ctx, mbedtls_entropy_context *entropy,
         mbedtls_ctr_drbg_context *ctr_drbg)
{
    const char pers[] = "ecdh";
    int ret = 0;
    //initialize contexts

    mbedtls_net_init(network_server);
    mbedtls_ecdh_init(ctx);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);

    //seed the random number generator
    ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                                (const unsigned char *)pers,
                                sizeof pers);
    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        return ret;
    }

    //use Curve SECP192R1
    ret = mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP192R1);
    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_ecp_group_load returned %d\n", ret);
        return ret;
    }

    ret = mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q, mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret);
        return ret;
    }
    return 0;
}

// static int generate_key_pair(mbedtls_ecp_group *ctx, mbedtls_mpi *d, mbedtls_ecp_point *Q, mbedtls_ctr_drbg_context *ctr_drbg)
// {
//     return mbedtls_ecdh_gen_public(ctx, d, Q,
//                                    mbedtls_ctr_drbg_random, ctr_drbg);
// }

static void dump_point(const char *title, mbedtls_ecp_point *point)
{
    printf("%s\n", title);
    mbedtls_mpi_write_file("X = ", &point->X, 10, NULL);
    mbedtls_mpi_write_file("Y = ", &point->Y, 10, NULL);
    mbedtls_mpi_write_file("Z = ", &point->Z, 10, NULL);
}

int get_curve_bitsize(mbedtls_ecp_group_id id)
{
    mbedtls_ecp_curve_info *info;
    info = mbedtls_ecp_curve_info_from_grp_id(id);
    printf("Bit size of curve: %d", info->bit_size);
    return info->bit_size;
}

static void dump_buf(const char *title, unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s", title);
    for (i = 0; i < len; i++)
        printf("%c%c", "0123456789ABCDEF"[buf[i] / 16],
               "0123456789ABCDEF"[buf[i] % 16]);
    printf("\n");
}

// static int export_pubkey(mbedtls_ecdh_context *ctx, unsigned char *buf, size_t buflen, size_t *len)
// {
//     int ret = mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q,
//                                              MBEDTLS_ECP_PF_UNCOMPRESSED, len, buf, buflen);
//     if (ret != 0)
//     {
//         printf("internal error, function returned %d\n", ret);
//         return ret;
//     }
//     dump_buf("in export_pubkey: ", buf, *len);
//     return 0;
// }

// static int import_pubkey(mbedtls_ecdh_context *ctx, unsigned char *buf, size_t buflen)
// {
//     int ret = mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Qp,
//                                             buf, buflen);
//     if (ret != 0)
//     {
//         printf("internal error, function returned %d\n", ret);
//         return ret;
//     }
//     dump_buf("in import_pubkey: ", buf, buflen);
//     return 0;
// }

int send_pubkey(mbedtls_ecdh_context *ctx, mbedtls_net_context *network_server)
{
    int ret;
    size_t olen;
    unsigned char pubkey_buffer[100];
    unsigned char length_buffer[2];
    //export server's public key to pubkey_buffer, save real length to olen
    ret = mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pubkey_buffer, sizeof pubkey_buffer);

    if (ret != 0)
    {
        printf("write point failed\n");
        return ret;
    }

    length_buffer[0] = (unsigned char)(olen);

    //send the length of the pubkey_buffer
    if ((ret = mbedtls_net_send(network_server, length_buffer, 2)) != 2)
    {
        printf("\n  ! mbedtls_net_send returned %d\n\n", ret);
        return ret;
    }

    if ((ret = mbedtls_net_send(network_server, pubkey_buffer, olen)) != (int)olen)
    {
        printf(" failed\n  ! mbedtls_net_send returned %d\n\n", ret);
        return ret;
    }
    return 0;
}

int recv_pubkey(mbedtls_ecdh_context *ctx,
                mbedtls_net_context *network_server)
{
    int ret;
    size_t olen;
    unsigned char pubkey_buffer[100];
    unsigned char length_buffer[2];
    //receive client's pubkey
    if ((ret = mbedtls_net_recv(network_server, length_buffer, 2)) != 2)
    {
        printf(" failed\n  ! mbedtls_net_recv returned %d\n\n", ret);
        return ret;
    }

    olen = length_buffer[0];

    memset(pubkey_buffer, 0, sizeof(pubkey_buffer));

    if ((ret = mbedtls_net_recv(network_server, pubkey_buffer, olen)) != (int)olen)
    {
        printf(" failed\n  ! mbedtls_net_recv returned %d\n\n", ret);
        return ret;
    }

    ret = mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Qp, pubkey_buffer, olen);
    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_ecp_point_read_binary returned %d\n\n", ret);
        return ret;
    }
    return 0;
}

int get_shared_secret(mbedtls_ecdh_context *ctx, unsigned char *shared_secret, size_t *olen, size_t blen, mbedtls_ctr_drbg_context *ctr_drbg)
{
    int ret = mbedtls_ecdh_calc_secret(ctx, olen, shared_secret, blen, mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_ecdh_calc_secret returned %d\n\n", ret);
        return ret;
    }
    return 0;
}

int connect_to_server(mbedtls_net_context *network_server)
{
    int ret;
    printf("\n  . Connecting to tcp/%s/%s....", SERVER_NAME, SERVER_PORT);
    fflush(stdout);

    ret = mbedtls_net_connect(network_server, SERVER_NAME,
                              SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        return ret;
    }
    printf(" Connected to server!\n");
    fflush(stdout);
    return ret;
}

int send_message(mbedtls_net_context *network_server, mbedtls_aes_context *aes, unsigned char *shared_secret)
{
    int ret;
    unsigned char message_buffer[256];
    unsigned char plain_text[256];
    printf("  . Client: ");
    fgets((char *)plain_text, sizeof(plain_text),stdin);
    // printf("...\n  . Encrypting and sending the ciphertext");
    fflush(stdout);

    ret = mbedtls_aes_setkey_enc(aes, shared_secret, 192);
    if (ret != 0)
    {
        printf("mbedtls_aes_setkey_enc returned %d\n\n", ret);
        return 1;
    }
    memcpy(message_buffer, plain_text, sizeof(message_buffer));
    ret = mbedtls_aes_crypt_ecb(aes, MBEDTLS_AES_ENCRYPT, message_buffer, message_buffer);
    if (ret != 0)
    {
        return 1;
    }

    ret = mbedtls_net_send(network_server, message_buffer, sizeof(message_buffer));
    if (ret != sizeof(message_buffer))
    {
        return 1;
    }
    if (strcmp((char *)plain_text, "bye\n") == 0)
    {
        printf("  . Disconnected from server\n");
        return 1;
    }
    // dump_buf("Text: ", message_buffer, sizeof message_buffer);// log ciphertext encrypted to console
    return 0;
}

int recv_message(mbedtls_net_context *network_server, mbedtls_aes_context *aes, unsigned char *shared_secret)
{
    int ret;
    unsigned char message_buffer[256];

    // printf("...\n  . Receiving and decrypting the ciphertext");
    // fflush(stdout);

    ret = mbedtls_aes_setkey_dec(aes, shared_secret, 192);
    if (ret != 0)
    {
        printf("mbedtls_aes_setkey_dec returned %d\n\n", ret);
        return 1;
    }

    ret = mbedtls_net_recv(network_server, message_buffer, sizeof(message_buffer));
    if (ret != sizeof(message_buffer))
    {
        printf(" failed\n  ! mbedtls_net_recv returned %d\n\n", ret);
        return 1;
    }

    // dump_buf("Text: ", message_buffer, sizeof(message_buffer));// log ciphertext recviced to console

    ret = mbedtls_aes_crypt_ecb(aes, MBEDTLS_AES_DECRYPT, message_buffer, message_buffer);
    if (ret != 0)
    {
        return 1;
    }
    if (strcmp((char *)message_buffer, "bye\n") == 0)
    {
        printf("Server disconected");
        return 1;
    }
    printf("\n  . Server: \"%s\"\n\n", (char *)message_buffer);
    return 0;
}

int main(int argc, char *argv[])
{
    if( argc != 2 ) {
        printf("How to use:\n ./ecdh_client SERVER");
        return;
    }
    printf("Server is %s", argv[1]);
    SERVER_NAME = argv[1];

    int ret = 1; // to check result when executed function: 0 -> successful
    mbedtls_net_context network_server;
    mbedtls_ecdh_context ctx_cli;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_aes_context aes;

    init(&network_server, &ctx_cli, &entropy, &ctr_drbg);
    mbedtls_aes_init(&aes);
    int key_size = get_curve_bitsize(ctx_cli.grp.id);

    printf("\n  . Connecting to server....");
    ret = connect_to_server(&network_server);
    if (ret != 0)
    {
        return 1;
    }

    ret = recv_pubkey(&ctx_cli, &network_server);
    if (ret != 0)
    {
        return 1;
    }
    ret = send_pubkey(&ctx_cli, &network_server);
    if (ret != 0)
    {
        return 1;
    }
    dump_point("Server public key: ", &ctx_cli.Qp);
    dump_point("Client public key: ", &ctx_cli.Q);

    size_t olen;
    unsigned char shared_secret[key_size / 8];
    ret = get_shared_secret(&ctx_cli, shared_secret, &olen, sizeof shared_secret, &ctr_drbg);
    if (ret != 0)
    {
        return 1;
    }
    dump_buf("Shared secret: ", shared_secret, sizeof shared_secret);
    while (1 == 1)
    {
        ret = recv_message(&network_server, &aes, &shared_secret);
        if (ret != 0)
        {
            break;
        }
        ret = send_message(&network_server, &aes, &shared_secret);
        if (ret != 0)
        {
            break;
        }
    }

    mbedtls_net_free(&network_server);
    return 0;
}