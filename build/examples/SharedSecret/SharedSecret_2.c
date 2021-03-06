
#include <openssl/evp.h>
#include <openssl/sha.h>

/* COSE ES256 (ECDSA over P-256 with SHA-256) public key */
typedef struct es256_pk {
	unsigned char	x[32];
	unsigned char	y[32];
} es256_pk_t;

/* COSE ES256 (ECDSA over P-256 with SHA-256) (secret) key */
typedef struct es256_sk {
	unsigned char	d[32];
} es256_sk_t;

typedef struct fido_blob {
	unsigned char	*ptr;
	size_t		 len;
} fido_blob_t;

fido_blob_t *		fido_blob_new(void);
void			fido_blob_free(fido_blob_t **);

void log_debug(const char *, ...);
void log_xxd(const void *, size_t);

//#include "fido.h"
#include "fido/es256.h"

//#include "types.h"
//#include "blob.h"


// ここで生成した秘密鍵sk , 取得した公開鍵pk
// ecdh = Shered Secret
static int
do_ecdh(
		const es256_sk_t *sk,		// (I )ここで生成した秘密鍵
		const es256_pk_t *pk,		// (I )Yubikeyから取得した公開鍵
		fido_blob_t **ecdh)			// ( O)生成したShered Secret
{
	EVP_PKEY	*pk_evp = NULL;
	EVP_PKEY	*sk_evp = NULL;
	EVP_PKEY_CTX	*ctx = NULL;
	fido_blob_t	*secret = NULL;
	int		 ok = -1;

	*ecdh = NULL;

	/* allocate blobs for secret & ecdh */
	if ((secret = fido_blob_new()) == NULL ||
	    (*ecdh = fido_blob_new()) == NULL)
		goto fail;

	// OpenSSLのEVP形式に変換する
	// sk -> sk_evp
	// pk -> pk_evp
	/* wrap the keys as openssl objects */
	if ((pk_evp = es256_pk_to_EVP_PKEY(pk)) == NULL ||
	    (sk_evp = es256_sk_to_EVP_PKEY(sk)) == NULL) {
		log_debug("%s: es256_to_EVP_PKEY", __func__);
		goto fail;
	}

	// 共有鍵生成
	// EVP_PKEY_derive_init() -> EVP_PKEY_derive_set_peer() -> EVP_PKEY_derive()

	// sk_evp⇒ ctx + pk_evp
	// EVP_PKEY_CTX_new()			公開鍵暗号コンテキスト ctx を 鍵 sk_evp で指定されるアルゴリズムを用いて生成する
	// EVP_PKEY_derive_init()		共有鍵生成:公開鍵暗号コンテキスト ctx を共有鍵生成用に初期化する．
	// EVP_PKEY_derive_set_peer()	共有鍵生成:公開鍵暗号コンテキスト ctx に公開情報 peer (pk_evp)を設定する．
	/* set ecdh parameters */
	if (
		(ctx =	EVP_PKEY_CTX_new(sk_evp, NULL)) == NULL ||
				EVP_PKEY_derive_init(ctx) <= 0 ||
				EVP_PKEY_derive_set_peer(ctx, pk_evp) <= 0) {
		log_debug("%s: EVP_PKEY_derive_init", __func__);
		goto fail;
	}

	/* perform ecdh */
	// EVP_PKEY_derive()
	//		公開鍵暗号コンテキスト ctx を用いて共有鍵生成を行う
	//		生成された鍵が secret
	if (EVP_PKEY_derive(ctx, NULL, &secret->len) <= 0 ||
	    (secret->ptr = calloc(1, secret->len)) == NULL ||
	    EVP_PKEY_derive(ctx, secret->ptr, &secret->len) <= 0) {
		log_debug("%s: EVP_PKEY_derive", __func__);
		goto fail;
	}

	/* use sha256 as a kdf on the resulting secret */
	// ↑で生成されたsecretのSHA256がecdh = Shered Secretとなる
	(*ecdh)->len = SHA256_DIGEST_LENGTH;
	if (((*ecdh)->ptr = calloc(1, (*ecdh)->len)) == NULL ||
	    SHA256(secret->ptr, secret->len, (*ecdh)->ptr) == NULL) {
		log_debug("%s: sha256", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (pk_evp != NULL)
		EVP_PKEY_free(pk_evp);
	if (sk_evp != NULL)
		EVP_PKEY_free(sk_evp);
	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);
	if (ok < 0)
		fido_blob_free(ecdh);

	fido_blob_free(&secret);

	return (ok);
}

int fido_createSharedSecret(
	es256_pk_t *public_key_aG,		// (I )Yubikeyから取得した公開鍵
	es256_pk_t **public_key_bG,		// ( O)ここで生成した公開鍵(bG)
	fido_blob_t **shearedSecret		// ( O)Sheared Secret
)
{
	es256_sk_t	*private_key_b = NULL; /* our private key */
	int		 r;

	*public_key_bG = NULL; /* our public key; returned */
	*shearedSecret = NULL; /* shared ecdh secret; returned */

	if ((private_key_b = es256_sk_new()) == NULL || (*public_key_bG = es256_pk_new()) == NULL) {
		r = -9;
		goto fail;
	}

	// sk=秘密鍵(b)とpk=公開鍵(bG)を生成
	//  ECDH P-256 key pair
	if (es256_sk_create(private_key_b) < 0 || es256_derive_pk(private_key_b, *public_key_bG) < 0) {
		log_debug("%s: es256_derive_pk", __func__);
		r = -9;
		goto fail;
	}

	// log
	log_debug("---");
	log_debug("%s:【Private Key-b】 ここで生成した秘密鍵(COSE ES256 (ECDSA over P-256 with SHA-256))", __func__);
	log_xxd(private_key_b->d, 32);
	log_debug("---");
	log_debug("%s:【Public Key-bG】ここで生成した公開鍵(COSE ES256 (ECDSA over P-256 with SHA-256) public key))", __func__);
	log_debug("x");
	log_xxd((*public_key_bG)->x, 32);
	log_debug("y");
	log_xxd((*public_key_bG)->y, 32);
	log_debug("---");
	log_debug("%s:【Public Key-aG】Yubikeyの公開鍵(COSE ES256 (ECDSA over P-256 with SHA-256) public key))", __func__);
	log_debug("x");
	log_xxd((public_key_aG)->x, 32);
	log_debug("y");
	log_xxd((public_key_aG)->y, 32);
	log_debug("---");

	// ここで生成した秘密鍵sk , 取得した公開鍵ak
	// をもとに sharedSecret を生成する
	if (do_ecdh(private_key_b, public_key_aG, shearedSecret) < 0) {
		log_debug("%s: do_ecdh", __func__);
		r = -9;
		goto fail;
	}

	log_debug("---");
	log_debug("%s:【Shared Secret】", __func__);
	log_xxd((*shearedSecret)->ptr, (*shearedSecret)->len);
	log_debug("---");

	r = 0;
fail:
	es256_sk_free(&private_key_b);
	if (r != 0) {
		es256_pk_free(public_key_bG);
		fido_blob_free(shearedSecret);
	}

	return (r);
}
