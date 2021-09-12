#include "mbedtls/config.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <string.h>
#define SERVER_NAME "localhost"
#define SERVER_PORT "11999"
#define PLAINTEXT "I am the client!"

static void init(mbedtls_net_context *network_listen, mbedtls_net_context *network_client,
                   mbedtls_ecdh_context *ctx, mbedtls_entropy_context *entropy,
                   mbedtls_ctr_drbg_context *ctr_drbg){
    const char pers[] = "ecdh";
    int ret = 0;
    //initialize contexts
    if(network_listen){
        mbedtls_net_init(network_listen);
    }
    mbedtls_net_init(network_client);
    mbedtls_ecdh_init(ctx);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);

    //seed the random number generator
    ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                                (const unsigned char *)pers,
                                sizeof pers);
    if (ret != 0)
    {
        printf("failed\n");
        return 1;
    }

    //use Curve SECP192R1
    mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP192R1);

    mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q,
                            mbedtls_ctr_drbg_random, ctr_drbg);

}

static void generate_key_pair(mbedtls_ecp_group *ctx, mbedtls_mpi *d, mbedtls_ecp_point *Q, mbedtls_ctr_drbg_context *ctr_drbg){
    mbedtls_ecdh_gen_public(ctx, d, Q,
                            mbedtls_ctr_drbg_random, ctr_drbg);
}

static void dump_point(const char *title, mbedtls_ecp_point *point){
    printf( "%s\n", title );
    mbedtls_mpi_write_file("X = ", &point->X, 10, NULL);
    mbedtls_mpi_write_file("Y = ", &point->Y, 10, NULL);
    mbedtls_mpi_write_file("Z = ", &point->Z, 10, NULL);
}

static int get_curve_bitsize(mbedtls_ecp_group_id id){
    mbedtls_ecp_curve_info *info ;
    info = mbedtls_ecp_curve_info_from_grp_id(id);
    printf("Bit size of curve: %d",info->bit_size);
    return info->bit_size;
}

static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    printf( "%s", title );
    for( i = 0; i < len; i++ )
        printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    printf( "\n" );
}

static void export_pubkey( mbedtls_ecdh_context *ctx, unsigned char * buf, size_t buflen, size_t * len)
{
    int ret = mbedtls_ecp_point_write_binary( &ctx->grp, &ctx->Q,
                MBEDTLS_ECP_PF_UNCOMPRESSED, len, buf, buflen );
    if( ret != 0 )
    {
        printf("internal error, function returned %d\n", ret);
        return;
    }
    dump_buf( "in export_pubkey: ", buf, *len );
}

static void import_pubkey(mbedtls_ecdh_context *ctx, unsigned char *buf, size_t buflen){
    int ret = mbedtls_ecp_point_read_binary( &ctx->grp, &ctx->Qp,
                buf, buflen );
    if( ret != 0 )
    {
        printf("internal error, function returned %d\n", ret);
        return;
    }
    dump_buf( "in import_pubkey: ", buf, buflen );
}

static void send_pubkey(mbedtls_ecdh_context *ctx,mbedtls_net_context *network_client){
    int ret;
    size_t olen;
    unsigned char pubkey_buffer[100];
    unsigned char length_buffer[2];
    //export server's public key to pubkey_buffer, save real length to olen
    mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pubkey_buffer, sizeof pubkey_buffer);

    if (ret != 0)
    {
        printf("write failed\n");
    }

    length_buffer[0] = (unsigned char)(olen);
    
    //send the length of the pubkey_buffer
    if ((ret = mbedtls_net_send(network_client, length_buffer, 2)) != 2)
    {
        printf("\n  ! mbedtls_net_send returned %d\n\n", ret);
    }

    if ((ret = mbedtls_net_send(network_client, pubkey_buffer, olen)) != (int)olen)
    {
        printf(" failed\n  ! mbedtls_net_send returned %d\n\n", ret);
    }
}

static void recv_pubkey(mbedtls_ecdh_context *ctx,
                        mbedtls_net_context *network_client){
    int ret;
    size_t olen;
    unsigned char pubkey_buffer[100];
    unsigned char length_buffer[2];
    //receive client's pubkey
    if ((ret = mbedtls_net_recv(network_client, length_buffer, 2)) != 2){
        printf(" failed\n  ! mbedtls_net_recv returned %d\n\n", ret);
    }

    olen = length_buffer[0];

    memset(pubkey_buffer, 0, sizeof(pubkey_buffer));
    
    if ((ret = mbedtls_net_recv(network_client, pubkey_buffer, olen)) != (int)olen){
        printf(" failed\n  ! mbedtls_net_recv returned %d\n\n", ret);
    }

    ret = mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Qp, pubkey_buffer, olen);
    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_ecp_point_read_binary returned %d\n\n", ret);
        return 1;
    }
}

static void get_shared_secret(mbedtls_ecdh_context *ctx, unsigned char * shared_secret, size_t * olen, size_t blen, mbedtls_ctr_drbg_context *ctr_drbg){
    int ret = mbedtls_ecdh_calc_secret(ctx, olen, shared_secret, blen, mbedtls_ctr_drbg_random, ctr_drbg);
    if(ret != 0){
        printf(" failed\n  ! mbedtls_ecdh_calc_secret returned %d\n\n", ret);
        return 1;
    }
}

static void connect_to_server(mbedtls_net_context *network_client){
    int ret;
    printf("\n  . Connecting to tcp/%s/%s....", SERVER_NAME, SERVER_PORT);
    fflush(stdout);

    ret = mbedtls_net_connect(network_client, SERVER_NAME,
                              SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        return 1;
    }
    printf(" Connected to server!\n");
    fflush(stdout);
}

void send_message(mbedtls_net_context *network_server, mbedtls_aes_context *aes, unsigned char * shared_secret)
{
    int ret;
    unsigned char message_buffer[256];
    unsigned long mess_size;
    printf( "...\n  . Encrypting and sending the ciphertext" );
    fflush( stdout );

    mbedtls_aes_setkey_enc( aes, shared_secret, 192 );
    memcpy( message_buffer, PLAINTEXT, sizeof(message_buffer));
    mbedtls_aes_crypt_ecb( aes, MBEDTLS_AES_ENCRYPT, message_buffer, message_buffer );

    ret = mbedtls_net_send(network_server, message_buffer, sizeof(message_buffer));

    dump_buf("Text: ", message_buffer, sizeof message_buffer);
}

void recv_message(mbedtls_net_context *server_fd, mbedtls_aes_context *aes, unsigned char *shared_secret){
    int ret;
    unsigned char mess_buffer[256];

    printf( "...\n  . Receiving and decrypting the ciphertext" );
    fflush( stdout );

    mbedtls_aes_setkey_dec( aes, shared_secret, 192 );

    ret = mbedtls_net_recv( server_fd, mess_buffer, sizeof(mess_buffer) ); 

    dump_buf("Text: ", mess_buffer, sizeof(mess_buffer));

    mbedtls_aes_crypt_ecb( aes, MBEDTLS_AES_DECRYPT, mess_buffer, mess_buffer);
    printf( "\n  . Received: \"%s\"\n\n", (char *) mess_buffer );

}

int main()
{
    int ret = 1; // to check result when executed function: 0 -> successful
    mbedtls_net_context server_fd;
    mbedtls_ecdh_context ctx_cli;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_aes_context aes;
    
    init(NULL, &server_fd, &ctx_cli, &entropy, &ctr_drbg);
    mbedtls_aes_init( &aes );
    int key_size = get_curve_bitsize(ctx_cli.grp.id);

    printf("\n  . Waiting for a remote connection....");
    connect_to_server(&server_fd);

    recv_pubkey(&ctx_cli, &server_fd);

    send_pubkey(&ctx_cli, &server_fd);

    dump_point("Server public key: ", &ctx_cli.Qp);
    dump_point("Client public key: ", &ctx_cli.Q);

    size_t olen;
    unsigned char shared_secret[key_size / 8];
    get_shared_secret(&ctx_cli, shared_secret, &olen, sizeof shared_secret, &ctr_drbg);
    
    dump_buf("Shared secret: ", shared_secret, sizeof shared_secret);

    recv_message(&server_fd, &aes, &shared_secret);

    send_message(&server_fd, &aes, &shared_secret);

    mbedtls_net_free(&server_fd);
    return 0;
}

