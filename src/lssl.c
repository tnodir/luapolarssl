/* Lua PolarSSL: SSLv3/TLSv1 shared functions */

#include "polarssl/ssl.h"
#include "polarssl/havege.h"
#include "polarssl/certs.h"


#define SSL_TYPENAME	"polarssl.ssl"

/*
 * Computing a "safe" DH-1024 prime can take a very
 * long time, so a precomputed value is provided below.
 * You may run dh_genprime to generate a new value.
 */
static const char * const default_dhm_P =
    "E4004C1F94182000103D883A448B3F80" \
    "2CE4B44A83301270002C20D0321CFD00" \
    "11CCEF784C26A400F43DFB901BCA7538" \
    "F2C6B176001CF5A0FD16D2C48B1D0C1C" \
    "F6AC8E1DA6BCC3B4E1F96B0564965300" \
    "FFA1D0B601EB2800F489AA512C4B248C" \
    "01F76949A60BB7F00A40B1EAB64BDD48" \
    "E8A700D60B7F1200FA8E77B0A979DABF";

static const char * const default_dhm_G = "4";

/* SSL Context environ. table reserved indexes */
enum {
    LSSL_CA_CERT = 1,  /* own trusted CA chain */
    LSSL_CA_CRL,  /* trusted CA CRLs */
    LSSL_OWN_CERT,  /* own X.509 certificate */
    LSSL_PEER_CN,  /* expected peer CN */
    LSSL_RNG,  /* random number generator callback */
    LSSL_PRNG,  /* context for the RNG function */
    LSSL_DBG,  /* debug callback */
    LSSL_PDBG,  /* context for the debug function */
    LSSL_BIO_RECV,  /* BIO read callback */
    LSSL_BIO_PRECV,  /* context for reading operations */
    LSSL_BIO_SEND,  /* BIO write callback */
    LSSL_BIO_PSEND,  /* context for writing operations */
    LSSL_SESS_GET,  /* (server) session get callback */
    LSSL_SESS_SET,  /* (server) session set callback */
    LSSL_SESS_CUR,  /* current session */
    LSSL_ENV_MAX
};

#define SSL_CIPHERS_COUNT	10

typedef struct {
    ssl_context ssl;
    ssl_session ssn;
    rsa_context rsa_key;
    havege_state hs;

    int ciphers[SSL_CIPHERS_COUNT + 1];

    lua_State *L;

    FILE *dbg_file;
    int dbg_level;

    int bio_len;
    unsigned char *bio_buf;
} lssl_context;

typedef int (*f_rng_t) (void *ctx);
typedef void (*f_dbg_t) (void *ctx, int level, const char *str);
typedef int (*f_bio_t) (void *ctx, unsigned char *buf, int n);


/*
 * Returns: ssl_udata
 */
static int
lssl_new (lua_State *L)
{
    lua_newuserdata(L, sizeof(lssl_context));

    luaL_getmetatable(L, SSL_TYPENAME);
    lua_setmetatable(L, -2);

    lua_newtable(L);  /* environ. */
    lua_setfenv(L, -2);
    return 1;
}

static int
lssl_bio_cb (lssl_context *ctx, unsigned char *buf, int n)
{
    if (ctx->bio_len == 0) {
	ctx->bio_len = n;
	ctx->bio_buf = buf;
    }
    else if (ctx->bio_buf == NULL) {
	n = ctx->bio_len;
	ctx->bio_len = 0;
	return n;
    }
    return -1;
}

/*
 * Arguments: ssl_udata
 * Returns: [buffer (ludata), length (number)]
 */
static int
lssl_bio_begin (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);

    if (ctx->bio_buf == NULL)
	lua_settop(L, 0);
    else {
	lua_pushlightuserdata(L, ctx->bio_buf);
	lua_pushinteger(L, ctx->bio_len);
    }
    return 2;
}

/*
 * Arguments: ssl_udata, length (number)
 */
static int
lssl_bio_end (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const int n = lua_tointeger(L, 2);

    if (ctx->bio_buf != NULL) {
	ctx->bio_buf = NULL;
	ctx->bio_len = n;
    }
    return 0;
}

/*
 * Arguments: ssl_udata
 * Returns: ssl_udata
 */
static int
lssl_init (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    ssl_context *ssl = &ctx->ssl;
    int res;

    memset(ctx, 0, sizeof(lssl_context));

    res = ssl_init(ssl);
    if (!res) {
	havege_init(&ctx->hs);
	ssl_set_rng(ssl, havege_rand, &ctx->hs);
	ssl_set_bio(ssl, (f_bio_t) lssl_bio_cb, ctx,
	 (f_bio_t) lssl_bio_cb, ctx);
	ssl_set_session(ssl, 1, 0, &ctx->ssn);
	ssl_set_ciphers(ssl, ssl_default_ciphers);
	ssl_set_dh_param(ssl, default_dhm_P, default_dhm_G);
    }
    return lssl_seterror(L, res);
}

/*
 * Arguments: ssl_udata
 */
static int
lssl_close (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    int i;

    lua_getfenv(L, 1);
    for (i = 1; i < LSSL_ENV_MAX; ++i) {
	lua_pushnil(L);
	lua_rawseti(L, -2, i);
    }

    rsa_free(&ctx->rsa_key);
    ssl_free(&ctx->ssl);

    memset(ctx, 0, sizeof(lssl_context));
    return 0;
}

/*
 * Arguments: ssl_udata, [upper_bound (number)]
 * Returns: number
 */
static int
lssl_havege_rand (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    unsigned int num, ub = lua_tointeger(L, 2);

    num = havege_rand(&ctx->hs);
    lua_pushnumber(L, ub ? num % ub : num);
    return 1;
}

/*
 * Arguments: ssl_udata, endpoint (string: "client", "server")
 * Returns: ssl_udata
 */
static int
lssl_set_endpoint (lua_State *L)
{
    ssl_context *ssl = checkudata(L, 1, SSL_TYPENAME);
    const char *s = luaL_checkstring(L, 2);
    const int endpoint = (*s == 's') ? SSL_IS_SERVER : SSL_IS_CLIENT;

    return lssl_seterror(L,
     (ssl_set_endpoint(ssl, endpoint), 0));
}

/*
 * Arguments: ssl_udata, authmode (string: "none", "optional", "required")
 * Returns: ssl_udata
 */
static int
lssl_set_authmode (lua_State *L)
{
    ssl_context *ssl = checkudata(L, 1, SSL_TYPENAME);
    const char *s = luaL_checkstring(L, 2);
    const int authmode = (*s == 'n') ? SSL_VERIFY_NONE
     : (*s == 'o' ? SSL_VERIFY_OPTIONAL : SSL_VERIFY_REQUIRED);

    return lssl_seterror(L,
     (ssl_set_authmode(ssl, authmode), 0));
}

/*
 * Arguments: ssl_udata, ..., environ. (table)
 */
static int
lssl_rng_cb (lssl_context *ctx)
{
    lua_State *L = ctx->L;
    int res;

    lua_rawgeti(L, -1, LSSL_RNG);  /* function */
    lua_rawgeti(L, -2, LSSL_PRNG);  /* rng_context */
    lua_call(L, 1, 1);
    res = lua_tointeger(L, -1);
    lua_pop(L, 1);
    return res;
}

/*
 * Arguments: ssl_udata, rng_callback (function), rng_context (any)
 * Returns: ssl_udata
 */
static int
lssl_set_rng (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const int is_nil = lua_isnil(L, 2);

    lua_settop(L, 3);
    lua_getfenv(L, 1);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, LSSL_RNG);
    lua_pushvalue(L, 3);
    lua_rawseti(L, -2, LSSL_PRNG);

    return lssl_seterror(L, (ssl_set_rng(&ctx->ssl,
     (is_nil ? havege_rand : (f_rng_t) lssl_rng_cb),
     (is_nil ? (void *) &ctx->hs : ctx)), 0));
}

/*
 * Arguments: ssl_udata, ..., environ. (table)
 */
static void
lssl_dbg_cb (lssl_context *ctx, int level, const char *str)
{
    lua_State *L = ctx->L;

    if (level >= ctx->dbg_level) return;

    if (ctx->dbg_file != NULL) {
	fputs(str, ctx->dbg_file);
	fflush(ctx->dbg_file);
	return;
    }

    lua_rawgeti(L, -1, LSSL_DBG);  /* function */
    lua_rawgeti(L, -2, LSSL_PDBG);  /* debug_context */
    lua_pushinteger(L, level);  /* level */
    lua_pushstring(L, str);  /* text */
    lua_call(L, 3, 0);
}

/*
 * Arguments: ssl_udata, file_udata | callback (function),
 *	debug_context (any)
 * Returns: ssl_udata
 */
static int
lssl_set_dbg (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const int is_nil = lua_isnil(L, 2);

    ctx->dbg_file = lua_isuserdata(L, 2)
     ? lua_unboxpointer(L, 2, LUA_FILEHANDLE) : NULL;

    lua_settop(L, 3);
    lua_getfenv(L, 1);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, LSSL_DBG);
    lua_pushvalue(L, 3);
    lua_rawseti(L, -2, LSSL_PDBG);

    return lssl_seterror(L, (ssl_set_dbg(&ctx->ssl,
     (is_nil ? NULL : (f_dbg_t) lssl_dbg_cb), ctx), 0));
}

/*
 * Arguments: ssl_udata, [debug_level (number)]
 * Returns: debug_level (number)
 */
static int
lssl_dbg_level (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const int nargs = lua_gettop(L);

    lua_pushinteger(L, ctx->dbg_level);
    if (nargs > 1) {
	ctx->dbg_level = lua_tointeger(L, 2);
    }
    return 1;
}

/*
 * Arguments: ssl_udata, ..., environ. (table)
 */
static int
lssl_bio_recv_cb (lssl_context *ctx, unsigned char *buf, int n)
{
    lua_State *L = ctx->L;
    const char *s;

    lua_rawgeti(L, -1, LSSL_BIO_RECV);  /* function */
    lua_rawgeti(L, -2, LSSL_BIO_PRECV);  /* recv_context */
    lua_pushinteger(L, n);  /* number of bytes */
    lua_call(L, 2, 1);
    s = lua_tolstring(L, -1, (size_t *) &n);  /* data */
    if (s)
	memcpy(buf, s, n);
    else
	n = -1;
    lua_pop(L, 1);
    return n;
}

/*
 * Arguments: ssl_udata, ..., environ. (table)
 */
static int
lssl_bio_send_cb (lssl_context *ctx, unsigned char *buf, int n)
{
    lua_State *L = ctx->L;
    int res;

    lua_rawgeti(L, -1, LSSL_BIO_SEND);  /* function */
    lua_rawgeti(L, -2, LSSL_BIO_PSEND);  /* send_context */
    lua_pushlstring(L, (char *) buf, n);  /* data */
    lua_call(L, 2, 2);
    res = lua_isnil(L, -2) ? -1
     : lua_tointeger(L, -1);  /* number of bytes */
    lua_pop(L, 2);
    return res;
}

/*
 * Arguments: ssl_udata,
 *	recv_callback (function), recv_context (any),
 *	send_callback (function), send_context (any)
 * Returns: ssl_udata
 */
static int
lssl_set_bio (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const int is_nil = lua_isnil(L, 2);

    lua_settop(L, 5);
    lua_getfenv(L, 1);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, LSSL_BIO_RECV);
    lua_pushvalue(L, 3);
    lua_rawseti(L, -2, LSSL_BIO_PRECV);
    lua_pushvalue(L, 4);
    lua_rawseti(L, -2, LSSL_BIO_SEND);
    lua_pushvalue(L, 5);
    lua_rawseti(L, -2, LSSL_BIO_PSEND);

    return lssl_seterror(L, (ssl_set_bio(&ctx->ssl,
     (f_bio_t) (is_nil ? lssl_bio_cb : lssl_bio_recv_cb), ctx,
     (f_bio_t) (is_nil ? lssl_bio_cb : lssl_bio_send_cb), ctx), 0));
}

/*
 * Arguments: ssl_udata, ..., environ. (table)
 */
static int
lssl_session_get_cb (lssl_context *ctx)
{
    lua_State *L = ctx->L;
    ssl_session *ssn;

    lua_rawgeti(L, -1, LSSL_SESS_GET);  /* function */
    lua_pushvalue(L, 1);  /* ssl_udata */
    lsession_pushid(L, &ctx->ssn);
    lua_call(L, 2, 1);
    ssn = lua_isuserdata(L, -1) ? checkudata(L, -1, SESSION_TYPENAME) : NULL;
    lua_rawseti(L, -2, LSSL_SESS_CUR);  /* [session_udata] */
    if (ssn) {
	memcpy(ctx->ssn.master, ssn->master, sizeof(ssn->master));
	return 0;
    }
    return 1;
}

/*
 * Arguments: ssl_udata, ..., environ. (table)
 */
static int
lssl_session_set_cb (lssl_context *ctx)
{
    lua_State *L = ctx->L;
    ssl_session *ssn;

    lua_rawgeti(L, -1, LSSL_SESS_SET);  /* function */
    lua_pushvalue(L, 1);  /* ssl_udata */
    lsession_pushid(L, &ctx->ssn);
    lua_call(L, 2, 1);
    ssn = lua_isuserdata(L, -1) ? checkudata(L, -1, SESSION_TYPENAME) : NULL;
    lua_rawseti(L, -2, LSSL_SESS_CUR);  /* [session_udata] */
    if (ssn) {
	*ssn = ctx->ssn;
	return 0;
    }
    return 1;
}

/*
 * Arguments: ssl_udata, get_session_callback (function),
 *	set_session_callback (function)
 * Returns: ssl_udata
 */
static int
lssl_set_scb (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const int is_nil = lua_isnil(L, 2);

    lua_settop(L, 3);
    lua_getfenv(L, 1);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, LSSL_SESS_GET);
    lua_pushvalue(L, 3);
    lua_rawseti(L, -2, LSSL_SESS_SET);

    return lssl_seterror(L, (ssl_set_scb(&ctx->ssl,
     is_nil ? NULL : (int (*)(ssl_context *)) lssl_session_get_cb,
     is_nil ? NULL : (int (*)(ssl_context *)) lssl_session_set_cb), 0));
}

/*
 * Arguments: ssl_udata, cipher_names (string) ...
 * Returns: ssl_udata
 */
static int
lssl_set_ciphers (lua_State *L)
{
    static const char *const cipher_names[] = {
#ifdef POLARSSL_ARC4_C
	"SSL_RSA_RC4_128_MD5",
	"SSL_RSA_RC4_128_SHA",
#endif
#ifdef POLARSSL_DES_C
	"SSL_RSA_DES_168_SHA",
	"SSL_EDH_RSA_DES_168_SHA",
#endif
#ifdef POLARSSL_AES_C
	"SSL_RSA_AES_128_SHA",
	"SSL_RSA_AES_256_SHA",
	"SSL_EDH_RSA_AES_256_SHA",
#endif
#ifdef POLARSSL_CAMELLIA_C
	"SSL_RSA_CAMELLIA_128_SHA",
	"SSL_EDH_RSA_CAMELLIA_128_SHA",
	"SSL_RSA_CAMELLIA_256_SHA",
	"SSL_EDH_RSA_CAMELLIA_256_SHA",
#endif
	NULL
    };
    static const int cipher_values[] = {
#ifdef POLARSSL_ARC4_C
	SSL_RSA_RC4_128_MD5,
	SSL_RSA_RC4_128_SHA,
#endif
#ifdef POLARSSL_DES_C
	SSL_RSA_DES_168_SHA,
	SSL_EDH_RSA_DES_168_SHA,
#endif
#ifdef POLARSSL_AES_C
	SSL_RSA_AES_128_SHA,
	SSL_RSA_AES_256_SHA,
	SSL_EDH_RSA_AES_256_SHA,
#endif
#ifdef POLARSSL_CAMELLIA_C
	SSL_RSA_CAMELLIA_128_SHA,
	SSL_EDH_RSA_CAMELLIA_128_SHA,
	SSL_RSA_CAMELLIA_256_SHA,
	SSL_EDH_RSA_CAMELLIA_256_SHA
#endif
    };

    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    int n = lua_gettop(L) - 1;
    int *ciphers;

    if (n == 0)
	ciphers = ssl_default_ciphers;
    else {
	const int is_table = lua_istable(L, 2);
	int *p = ctx->ciphers;
	int i;

	if (is_table)
	    n = lua_rawlen(L, 2);
	if (n > SSL_CIPHERS_COUNT) n = SSL_CIPHERS_COUNT;
	for (i = 1; i <= n; ++i) {
	    if (is_table)
		lua_rawgeti(L, 2, i);
	    else
		lua_pushvalue(L, 1 + i);
	    *p++ = cipher_values[
	     luaL_checkoption(L, -1, NULL, cipher_names)];
	    lua_pop(L, 1);
	}
	*p++ = 0;
	ciphers = ctx->ciphers;
    }

    return lssl_seterror(L,
     (ssl_set_ciphers(&ctx->ssl, ciphers), 0));
}

/*
 * Arguments: ssl_udata, peer_cn (string)
 * Returns: ssl_udata
 */
static int
lssl_set_peer_cn (lua_State *L)
{
    ssl_context *ssl = checkudata(L, 1, SSL_TYPENAME);
    const char *peer_cn = lua_tostring(L, 2);

    lua_settop(L, 2);
    lua_getfenv(L, 1);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, LSSL_PEER_CN);

    ssl->peer_cn = peer_cn;
    return lssl_seterror(L, 0);
}

/*
 * Arguments: ssl_udata, x509_cert_udata, [chain_offset (number)]
 * Returns: ssl_udata
 */
static int
lssl_set_ca_cert (lua_State *L)
{
    ssl_context *ssl = checkudata(L, 1, SSL_TYPENAME);
    x509_cert *crt = checkudata(L, 2, X509_CERT_TYPENAME);
    int off = lua_tointeger(L, 3);

    lua_settop(L, 2);
    lua_getfenv(L, 1);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, LSSL_CA_CERT);

    while (off--) {
	crt = crt->next;
	if (!crt)
	    return lssl_seterror(L, 1);
    }
    ssl->ca_chain = crt;
    return lssl_seterror(L, 0);
}

/*
 * Arguments: ssl_udata, x509_crl_udata, [chain_offset (number)]
 * Returns: ssl_udata
 */
static int
lssl_set_ca_crl (lua_State *L)
{
    ssl_context *ssl = checkudata(L, 1, SSL_TYPENAME);
    x509_crl *crl = checkudata(L, 2, X509_CRL_TYPENAME);
    int off = lua_tointeger(L, 3);

    lua_settop(L, 2);
    lua_getfenv(L, 1);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, LSSL_CA_CRL);

    while (off--) {
	crl = crl->next;
	if (!crl)
	    return lssl_seterror(L, 1);
    }
    ssl->ca_crl = crl;
    return lssl_seterror(L, 0);
}

/*
 * Arguments: ssl_udata, x509_cert_udata, [chain_offset (number)]
 * Returns: ssl_udata
 */
static int
lssl_set_own_cert (lua_State *L)
{
    ssl_context *ssl = checkudata(L, 1, SSL_TYPENAME);
    x509_cert *crt = checkudata(L, 2, X509_CERT_TYPENAME);
    int off = lua_tointeger(L, 3);

    lua_settop(L, 2);
    lua_getfenv(L, 1);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, LSSL_OWN_CERT);

    while (off--) {
	crt = crt->next;
	if (!crt)
	    return lssl_seterror(L, 1);
    }
    ssl->own_cert = crt;
    return lssl_seterror(L, 0);
}

static int
lssl_set_rsa (lua_State *L, lssl_context *ctx, rsa_context *rsa_key, int res)
{
    if (!res) {
	rsa_free(&ctx->rsa_key);
	ctx->rsa_key = *rsa_key;
	ctx->ssl.rsa_key = &ctx->rsa_key;
    }
    return lssl_seterror(L, res);
}

/*
 * Arguments: ssl_udata, key (string), [password (string)]
 * Returns: ssl_udata
 */
static int
lssl_set_rsa_key (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    size_t keylen, pwdlen;
    const unsigned char *key = (const unsigned char *) luaL_checklstring(L, 2, &keylen);
    const unsigned char *pwd = (const unsigned char *) lua_tolstring(L, 3, &pwdlen);
    rsa_context rsa_key;

    return lssl_set_rsa(L, ctx, &rsa_key,
     x509parse_key(&rsa_key, key, keylen, pwd, pwdlen));
}

/*
 * Arguments: ssl_udata, path (string), [password (string)]
 * Returns: ssl_udata
 */
static int
lssl_set_rsa_keyfile (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const char *path = luaL_checkstring(L, 2);
    const char *pwd = lua_tostring(L, 3);
    rsa_context rsa_key;

    return lssl_set_rsa(L, ctx, &rsa_key,
     x509parse_keyfile(&rsa_key, path, pwd));
}

/*
 * Arguments: ssl_udata
 * Returns: ssl_udata
 */
static int
lssl_set_rsa_keytest (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const char *key = (ctx->ssl.endpoint == SSL_IS_SERVER)
     ? test_srv_key : test_cli_key;
    rsa_context rsa_key;

    return lssl_set_rsa(L, ctx, &rsa_key,
     x509parse_key(&rsa_key, (const unsigned char *) key, strlen(key), NULL, 0));
}

/*
 * Arguments: ssl_udata, dhm_P (string), dhm_G (string)
 * Returns: ssl_udata
 */
static int
lssl_set_dh_param (lua_State *L)
{
    ssl_context *ssl = checkudata(L, 1, SSL_TYPENAME);
    const char *dhm_P = lua_tostring(L, 2);
    const char *dhm_G = lua_tostring(L, 3);

    return lssl_seterror(L, ssl_set_dh_param(ssl,
     dhm_P ? dhm_P : default_dhm_P,
     dhm_G ? dhm_G : default_dhm_G));
}

/*
 * Arguments: ssl_udata, hostname (string)
 * Returns: ssl_udata
 */
static int
lssl_set_hostname (lua_State *L)
{
    ssl_context *ssl = checkudata(L, 1, SSL_TYPENAME);
    const char *hostname = luaL_checkstring(L, 2);

    return lssl_seterror(L, ssl_set_hostname(ssl, hostname));
}

/*
 * Arguments: ssl_udata
 * Returns: number
 */
static int
lssl_get_bytes_avail (lua_State *L)
{
    ssl_context *ssl = checkudata(L, 1, SSL_TYPENAME);

    lua_pushinteger(L, ssl_get_bytes_avail(ssl));
    return 1;
}

/*
 * Arguments: ssl_udata
 * Returns: expired (boolean), revoked (boolean),
 *	cn_mismatch (boolean), not_trusted (boolean)
 */
static int
lssl_get_verify_result (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const int res = ssl_get_verify_result(&ctx->ssl);

    lua_pushboolean(L, res & BADCERT_EXPIRED);
    lua_pushboolean(L, res & BADCERT_REVOKED);
    lua_pushboolean(L, res & BADCERT_CN_MISMATCH);
    lua_pushboolean(L, res & BADCERT_NOT_TRUSTED);
    return 4;
}

/*
 * Arguments: ssl_udata
 * Returns: cipher_name (string)
 */
static int
lssl_get_cipher (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);

    lua_pushstring(L, ssl_get_cipher(&ctx->ssl));
    return 1;
}

/*
 * Arguments: ssl_udata, x509_cert_udata
 * Returns: ssl_udata
 */
static int
lssl_get_peer_cert (lua_State *L)
{
    ssl_context *ssl = checkudata(L, 1, SSL_TYPENAME);
    x509_cert *crt = checkudata(L, 2, X509_CERT_TYPENAME);

    *crt = *ssl->peer_cert;
    return lssl_seterror(L, 0);
}

/*
 * Arguments: ssl_udata
 * Returns: ssl_udata
 */
static int
lssl_handshake (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);

    lua_getfenv(L, 1);

    ctx->L = L;
    return lssl_seterror(L, ssl_handshake(&ctx->ssl));
}

/*
 * Arguments: ssl_udata, [buffer (ludata), length (number)]
 * Returns: number | string
 */
static int
lssl_read (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const int is_udata = lua_isuserdata(L, 2);
    unsigned char buffer[4096];
    unsigned char *buf = is_udata ? lua_touserdata(L, 2) : buffer;
    const int len = is_udata ? lua_tointeger(L, 3) : (int) sizeof(buffer);
    int res;

    lua_settop(L, 1);
    lua_getfenv(L, 1);

    ctx->L = L;
    res = ssl_read(&ctx->ssl, buf, len);
    if (res >= 0) {
	if (is_udata)
	    lua_pushinteger(L, res);
	else
	    lua_pushlstring(L, (char *) buf, res);
	return 1;
    }
    return lssl_seterror(L, res);
}

/*
 * Arguments: ssl_udata, string | {buffer (ludata), length (number)}
 * Returns: [success/partial (boolean), count (number)]
 */
static int
lssl_write (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);
    const int is_udata = lua_isuserdata(L, 2);
    size_t len = is_udata ? lua_tointeger(L, 3) : 0;
    const unsigned char *buf = is_udata ? lua_touserdata(L, 2)
     : lua_tolstring(L, 2, &len);
    int res;

    lua_settop(L, 2);
    lua_getfenv(L, 1);

    ctx->L = L;
    res = ssl_write(&ctx->ssl, buf, len);
    if (res >= 0) {
	lua_pushboolean(L, (res == (int) len));
	lua_pushinteger(L, res);
	return 2;
    }
    return lssl_seterror(L, res);
}

/*
 * Arguments: ssl_udata
 * Returns: ssl_udata
 */
static int
lssl_close_notify (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);

    lua_getfenv(L, 1);

    ctx->L = L;
    return lssl_seterror(L, ssl_close_notify(&ctx->ssl));
}

/*
 * Arguments: ssl_udata
 * Returns: string
 */
static int
lssl_tostring (lua_State *L)
{
    lssl_context *ctx = checkudata(L, 1, SSL_TYPENAME);

    lua_pushfstring(L, SSL_TYPENAME " (%p)", ctx);
    return 1;
}


#define SSL_METHODS \
    {"ssl",		lssl_new}

static luaL_reg lssl_meth[] = {
    {"init",			lssl_init},
    {"close",			lssl_close},
    {"bio_begin",		lssl_bio_begin},
    {"bio_end",			lssl_bio_end},
    {"havege_rand",		lssl_havege_rand},
    {"set_endpoint",		lssl_set_endpoint},
    {"set_authmode",		lssl_set_authmode},
    {"set_rng",			lssl_set_rng},
    {"set_dbg",			lssl_set_dbg},
    {"dbg_level",		lssl_dbg_level},
    {"set_bio",			lssl_set_bio},
    {"set_scb",			lssl_set_scb},
    {"set_ciphers",		lssl_set_ciphers},
    {"set_peer_cn",		lssl_set_peer_cn},
    {"set_ca_cert",		lssl_set_ca_cert},
    {"set_ca_crl",		lssl_set_ca_crl},
    {"set_own_cert",		lssl_set_own_cert},
    {"set_rsa_key",		lssl_set_rsa_key},
    {"set_rsa_keyfile",		lssl_set_rsa_keyfile},
    {"set_rsa_keytest",		lssl_set_rsa_keytest},
    {"set_dh_param",		lssl_set_dh_param},
    {"set_hostname",		lssl_set_hostname},
    {"get_bytes_avail",		lssl_get_bytes_avail},
    {"get_verify_result",	lssl_get_verify_result},
    {"get_cipher",		lssl_get_cipher},
    {"get_peer_cert",		lssl_get_peer_cert},
    {"handshake",		lssl_handshake},
    {"read",			lssl_read},
    {"write",			lssl_write},
    {"close_notify",		lssl_close_notify},
    {"__tostring",		lssl_tostring},
    {"__gc",			lssl_close},
    {NULL, NULL}
};
