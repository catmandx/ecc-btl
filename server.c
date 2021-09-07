#include "mbedtls/config.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define SERVER_NAME "localhost"
#define SERVER_PORT "11999"
#define PLAINTEXT "==Hello there!=="

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
    dump_buf("in send pubkey: length buffer: ", length_buffer, 2);
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
    printf(" ret: %d\n\n", ret);

    olen = length_buffer[0];

    memset(pubkey_buffer, 0, sizeof(pubkey_buffer));
    
    if ((ret = mbedtls_net_recv(network_client, pubkey_buffer, olen)) != (int)olen){
        printf(" failed\n  ! mbedtls_net_recv returned %d\n\n", ret);
    }

    printf(" ret: %d\n\n", ret);
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

static void listen_and_accept(mbedtls_net_context *network_listen, mbedtls_net_context *network_client){
    int ret = mbedtls_net_bind(network_listen, NULL, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        return 1;
    }
    //waits for a connection to accept
    ret = mbedtls_net_accept(network_listen, network_client, NULL, 0, NULL);

    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        return 1;
    }
    printf("Client connected!\n");
}

int main()
{
    int ret = 1; // to check result when executed function: 0 -> successful
    mbedtls_net_context network_listen, network_client;
    mbedtls_ecdh_context ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    init(&network_listen, &network_client, &ctx_srv, &entropy, &ctr_drbg);
    int key_size = get_curve_bitsize(ctx_srv.grp.id);

    printf("\n  . Waiting for a remote connection....");
    fflush(stdout);

    listen_and_accept(&network_listen, &network_client);

    send_pubkey(&ctx_srv, &network_client);

    recv_pubkey(&ctx_srv, &network_client);
    
    //done transaction
    dump_point("Server's pubkey:",&ctx_srv.Q);
    dump_point("Client's pubkey: ", &ctx_srv.Qp);


    size_t olen;
    unsigned char shared_secret[key_size / 8];
    get_shared_secret(&ctx_srv, shared_secret, &olen, sizeof shared_secret, &ctr_drbg);
    
    dump_buf("Shared secret: ", shared_secret, sizeof shared_secret);
    
    mbedtls_net_free(&network_client);
    return 1;
}

