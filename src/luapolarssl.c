/* Lua PolarSSL */

#include "common.h"

#include "polarssl/config.h"
#include "polarssl/timing.h"

#ifdef POLARSSL_AES_C
#include "laes.c"
#endif
#include "lbase64.c"
#ifdef POLARSSL_CAMELLIA_C
#include "lcamellia.c"
#endif
#ifdef POLARSSL_DES_C
#include "ldes.c"
#endif
#include "lhash.c"
#ifdef POLARSSL_PADLOCK_C
#include "lpadlock.c"
#endif
#include "lsession.c"
#include "lx509_cert.c"
#include "lx509_crl.c"
#include "lssl.c"
#include "lmpi.c"


/*
 * Returns: self | nil, string
 */
static int
lssl_seterror (lua_State *L, int err)
{
    const char *s, *s2 = NULL;

    if (!err) {
	lua_settop(L, 1);
	return 1;
    }
    if (err >= (POLARSSL_ERR_X509_VALUE_TO_LENGTH | POLARSSL_ERR_ASN1_INVALID_DATA)  /* -772 */
     && err <= (POLARSSL_ERR_X509_FEATURE_UNAVAILABLE | POLARSSL_ERR_ASN1_INVALID_DATA)) {  /* -4 */
	switch (err & 0x1F) {
	case POLARSSL_ERR_ASN1_OUT_OF_DATA: s2 = "ASN1_OUT_OF_DATA"; break;
	case POLARSSL_ERR_ASN1_UNEXPECTED_TAG: s2 = "ASN1_UNEXPECTED_TAG"; break;
	case POLARSSL_ERR_ASN1_INVALID_LENGTH: s2 = "ASN1_INVALID_LENGTH"; break;
	case POLARSSL_ERR_ASN1_LENGTH_MISMATCH: s2 = "ASN1_LENGTH_MISMATCH"; break;
	case POLARSSL_ERR_ASN1_INVALID_DATA: s2 = "ASN1_INVALID_DATA"; break;
	default: s2 = "UNKNOWN";
	}
	err &= ~0x1F;
    }
    switch (err) {
#ifdef POLARSSL_AES_C
    case POLARSSL_ERR_AES_INVALID_KEY_LENGTH: s = "AES_INVALID_KEY_LENGTH"; break;
    case POLARSSL_ERR_AES_INVALID_INPUT_LENGTH: s = "AES_INVALID_INPUT_LENGTH"; break;
#endif

    case POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL: s = "BASE64_BUFFER_TOO_SMALL"; break;
    case POLARSSL_ERR_BASE64_INVALID_CHARACTER: s = "BASE64_INVALID_CHARACTER"; break;

#ifdef POLARSSL_CAMELLIA_C
    case POLARSSL_ERR_CAMELLIA_INVALID_KEY_LENGTH: s = "CAMELLIA_INVALID_KEY_LENGTH"; break;
    case POLARSSL_ERR_CAMELLIA_INVALID_INPUT_LENGTH: s = "CAMELLIA_INVALID_INPUT_LENGTH"; break;
#endif

#ifdef POLARSSL_DES_C
    case POLARSSL_ERR_DES_INVALID_INPUT_LENGTH: s = "DES_INVALID_INPUT_LENGTH"; break;
#endif

    case POLARSSL_ERR_DHM_BAD_INPUT_DATA: s = "DHM_BAD_INPUT_DATA"; break;
    case POLARSSL_ERR_DHM_READ_PARAMS_FAILED: s = "DHM_READ_PARAMS_FAILED"; break;
    case POLARSSL_ERR_DHM_MAKE_PARAMS_FAILED: s = "DHM_MAKE_PARAMS_FAILED"; break;
    case POLARSSL_ERR_DHM_READ_PUBLIC_FAILED: s = "DHM_READ_PUBLIC_FAILED"; break;
    case POLARSSL_ERR_DHM_MAKE_PUBLIC_FAILED: s = "DHM_MAKE_PUBLIC_FAILED"; break;
    case POLARSSL_ERR_DHM_CALC_SECRET_FAILED: s = "DHM_CALC_SECRET_FAILED"; break;

    case POLARSSL_ERR_MPI_FILE_IO_ERROR: s = "MPI_FILE_IO_ERROR"; break;
    case POLARSSL_ERR_MPI_BAD_INPUT_DATA: s = "MPI_BAD_INPUT_DATA"; break;
    case POLARSSL_ERR_MPI_INVALID_CHARACTER: s = "MPI_INVALID_CHARACTER"; break;
    case POLARSSL_ERR_MPI_BUFFER_TOO_SMALL: s = "MPI_BUFFER_TOO_SMALL"; break;
    case POLARSSL_ERR_MPI_NEGATIVE_VALUE: s = "MPI_NEGATIVE_VALUE"; break;
    case POLARSSL_ERR_MPI_DIVISION_BY_ZERO: s = "MPI_DIVISION_BY_ZERO"; break;
    case POLARSSL_ERR_MPI_NOT_ACCEPTABLE: s = "MPI_NOT_ACCEPTABLE"; break;

#ifdef POLARSSL_ERR_PADLOCK_DATA_MISALIGNED
    case POLARSSL_ERR_PADLOCK_DATA_MISALIGNED: s = "PADLOCK_DATA_MISALIGNED"; break;
#endif

    case POLARSSL_ERR_RSA_BAD_INPUT_DATA: s = "RSA_BAD_INPUT_DATA"; break;
    case POLARSSL_ERR_RSA_INVALID_PADDING: s = "RSA_INVALID_PADDING"; break;
    case POLARSSL_ERR_RSA_KEY_GEN_FAILED: s = "RSA_KEY_GEN_FAILED"; break;
    case POLARSSL_ERR_RSA_KEY_CHECK_FAILED: s = "RSA_KEY_CHECK_FAILED"; break;
    case POLARSSL_ERR_RSA_PUBLIC_FAILED: s = "RSA_PUBLIC_FAILED"; break;
    case POLARSSL_ERR_RSA_PRIVATE_FAILED: s = "RSA_PRIVATE_FAILED"; break;
    case POLARSSL_ERR_RSA_VERIFY_FAILED: s = "RSA_VERIFY_FAILED"; break;
    case POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE: s = "RSA_OUTPUT_TOO_LARGE"; break;
    case POLARSSL_ERR_RSA_RNG_FAILED: s = "RSA_RNG_FAILED"; break;

    case POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE: s = "SSL_FEATURE_UNAVAILABLE"; break;
    case POLARSSL_ERR_SSL_BAD_INPUT_DATA: s = "SSL_BAD_INPUT_DATA"; break;
    case POLARSSL_ERR_SSL_INVALID_MAC: s = "SSL_INVALID_MAC"; break;
    case POLARSSL_ERR_SSL_INVALID_RECORD: s = "SSL_INVALID_RECORD"; break;
    case POLARSSL_ERR_SSL_INVALID_MODULUS_SIZE: s = "SSL_INVALID_MODULUS_SIZE"; break;
    case POLARSSL_ERR_SSL_UNKNOWN_CIPHER: s = "SSL_UNKNOWN_CIPHER"; break;
    case POLARSSL_ERR_SSL_NO_CIPHER_CHOSEN: s = "SSL_NO_CIPHER_CHOSEN"; break;
    case POLARSSL_ERR_SSL_NO_SESSION_FOUND: s = "SSL_NO_SESSION_FOUND"; break;
    case POLARSSL_ERR_SSL_NO_CLIENT_CERTIFICATE: s = "SSL_NO_CLIENT_CERTIFICATE"; break;
    case POLARSSL_ERR_SSL_CERTIFICATE_TOO_LARGE: s = "SSL_CERTIFICATE_TOO_LARGE"; break;
    case POLARSSL_ERR_SSL_CERTIFICATE_REQUIRED: s = "SSL_CERTIFICATE_REQUIRED"; break;
    case POLARSSL_ERR_SSL_PRIVATE_KEY_REQUIRED: s = "SSL_PRIVATE_KEY_REQUIRED"; break;
    case POLARSSL_ERR_SSL_CA_CHAIN_REQUIRED: s = "SSL_CA_CHAIN_REQUIRED"; break;
    case POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE: s = "SSL_UNEXPECTED_MESSAGE"; break;
    case POLARSSL_ERR_SSL_FATAL_ALERT_MESSAGE: s = "SSL_FATAL_ALERT_MESSAGE"; break;
    case POLARSSL_ERR_SSL_PEER_VERIFY_FAILED: s = "SSL_PEER_VERIFY_FAILED"; break;
    case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY: s = "SSL_PEER_CLOSE_NOTIFY"; break;
    case POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO: s = "SSL_BAD_HS_CLIENT_HELLO"; break;
    case POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO: s = "SSL_BAD_HS_SERVER_HELLO"; break;
    case POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE: s = "SSL_BAD_HS_CERTIFICATE"; break;
    case POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST: s = "SSL_BAD_HS_CERTIFICATE_REQUEST"; break;
    case POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE: s = "SSL_BAD_HS_SERVER_KEY_EXCHANGE"; break;
    case POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO_DONE: s = "SSL_BAD_HS_SERVER_HELLO_DONE"; break;
    case POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE: s = "SSL_BAD_HS_CLIENT_KEY_EXCHANGE"; break;
    case POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY: s = "SSL_BAD_HS_CERTIFICATE_VERIFY"; break;
    case POLARSSL_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC: s = "SSL_BAD_HS_CHANGE_CIPHER_SPEC"; break;
    case POLARSSL_ERR_SSL_BAD_HS_FINISHED: s = "SSL_BAD_HS_FINISHED"; break;

    case POLARSSL_ERR_X509_FEATURE_UNAVAILABLE: s = "X509_FEATURE_UNAVAILABLE"; break;
    case POLARSSL_ERR_X509_CERT_INVALID_PEM: s = "X509_CERT_INVALID_PEM"; break;
    case POLARSSL_ERR_X509_CERT_INVALID_FORMAT: s = "X509_CERT_INVALID_FORMAT"; break;
    case POLARSSL_ERR_X509_CERT_INVALID_VERSION: s = "X509_CERT_INVALID_VERSION"; break;
    case POLARSSL_ERR_X509_CERT_INVALID_SERIAL: s = "X509_CERT_INVALID_SERIAL"; break;
    case POLARSSL_ERR_X509_CERT_INVALID_ALG: s = "X509_CERT_INVALID_ALG"; break;
    case POLARSSL_ERR_X509_CERT_INVALID_NAME: s = "X509_CERT_INVALID_NAME"; break;
    case POLARSSL_ERR_X509_CERT_INVALID_DATE: s = "X509_CERT_INVALID_DATE"; break;
    case POLARSSL_ERR_X509_CERT_INVALID_PUBKEY: s = "X509_CERT_INVALID_PUBKEY"; break;
    case POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE: s = "X509_CERT_INVALID_SIGNATURE"; break;
    case POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS: s = "X509_CERT_INVALID_EXTENSIONS"; break;
    case POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION: s = "X509_CERT_UNKNOWN_VERSION"; break;
    case POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG: s = "X509_CERT_UNKNOWN_SIG_ALG"; break;
    case POLARSSL_ERR_X509_CERT_UNKNOWN_PK_ALG: s = "X509_CERT_UNKNOWN_PK_ALG"; break;
    case POLARSSL_ERR_X509_CERT_SIG_MISMATCH: s = "X509_CERT_SIG_MISMATCH"; break;
    case POLARSSL_ERR_X509_CERT_VERIFY_FAILED: s = "X509_CERT_VERIFY_FAILED"; break;
    case POLARSSL_ERR_X509_KEY_INVALID_PEM: s = "X509_KEY_INVALID_PEM"; break;
    case POLARSSL_ERR_X509_KEY_INVALID_VERSION: s = "X509_KEY_INVALID_VERSION"; break;
    case POLARSSL_ERR_X509_KEY_INVALID_FORMAT: s = "X509_KEY_INVALID_FORMAT"; break;
    case POLARSSL_ERR_X509_KEY_INVALID_ENC_IV: s = "X509_KEY_INVALID_ENC_IV"; break;
    case POLARSSL_ERR_X509_KEY_UNKNOWN_ENC_ALG: s = "X509_KEY_UNKNOWN_ENC_ALG"; break;
    case POLARSSL_ERR_X509_KEY_PASSWORD_REQUIRED: s = "X509_KEY_PASSWORD_REQUIRED"; break;
    case POLARSSL_ERR_X509_KEY_PASSWORD_MISMATCH: s = "X509_KEY_PASSWORD_MISMATCH"; break;
    case POLARSSL_ERR_X509_POINT_ERROR: s = "X509_POINT_ERROR"; break;
    case POLARSSL_ERR_X509_VALUE_TO_LENGTH: s = "X509_VALUE_TO_LENGTH"; break;

    case -1: s = "BAD_FILE"; break;
    case -2: s = "FILE_IO_ERROR"; break;

    case 1: s = "OUT_OF_MEMORY"; break;
    default: s = "UNKNOWN";
    }
    lua_pushnil(L);
    lua_pushfstring(L, "%s%s%s", s, (s2 ? ": " : ""), (s2 ? s2 : ""));
    lua_pushvalue(L, -1);
    lua_setglobal(L, LSSL_ERROR_MESSAGE);
    return 2;
}

/*
 * Returns: number
 */
static int
lssl_hardclock (lua_State *L)
{
    lua_pushnumber(L, hardclock());
    return 1;
}


static luaL_reg polarssl_lib[] = {
    {"hardclock",	lssl_hardclock},
    BASE64_METHODS,
    HASH_METHODS,
    MPI_METHODS,
    SESSION_METHODS,
    SSL_METHODS,
    X509_CERT_METHODS,
    X509_CRL_METHODS,
    {NULL, NULL}
};

static void
createmeta (lua_State *L)
{
    struct meta_s {
	const char *tname;
	luaL_reg *meth;
    } meta[] = {
	{HASH_TYPENAME,		lhash_meth},
	{MPI_TYPENAME,		lmpi_meth},
	{SESSION_TYPENAME,	lsession_meth},
	{SSL_TYPENAME,		lssl_meth},
	{X509_CERT_TYPENAME,	lx509_cert_meth},
	{X509_CRL_TYPENAME,	lx509_crl_meth},
    };
    int i;

    for (i = 0; i < (int) (sizeof(meta) / sizeof(struct meta_s)); ++i) {
	luaL_newmetatable(L, meta[i].tname);
	lua_pushvalue(L, -1);  /* push metatable */
	lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
	luaL_register(L, NULL, meta[i].meth);
	lua_pop(L, 1);
    }
}


LUALIB_API int
luaopen_polarssl (lua_State *L)
{
    luaL_register(L, LUA_POLARSSLLIBNAME, polarssl_lib);
    createmeta(L);
    return 1;
}
