/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "fido.h"
#include "fido/es256.h"

// �����Ő��������閧��sk , �擾�������J��pk
// ecdh = Shered Secret
static int
do_ecdh(
		const es256_sk_t *sk,		// (I )�����Ő��������閧��
		const es256_pk_t *pk,		// (I )Yubikey����擾�������J��
		fido_blob_t **ecdh)			// ( O)��������Shered Secret
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

	// OpenSSL��EVP�`���ɕϊ�����
	// sk -> sk_evp
	// pk -> pk_evp
	/* wrap the keys as openssl objects */
	if ((pk_evp = es256_pk_to_EVP_PKEY(pk)) == NULL ||
	    (sk_evp = es256_sk_to_EVP_PKEY(sk)) == NULL) {
		log_debug("%s: es256_to_EVP_PKEY", __func__);
		goto fail;
	}

	// ���L������
	// EVP_PKEY_derive_init() -> EVP_PKEY_derive_set_peer() -> EVP_PKEY_derive()

	// sk_evp�� ctx + pk_evp
	// EVP_PKEY_CTX_new()			���J���Í��R���e�L�X�g ctx �� �� sk_evp �Ŏw�肳���A���S���Y����p���Đ�������
	// EVP_PKEY_derive_init()		���L������:���J���Í��R���e�L�X�g ctx �����L�������p�ɏ���������D
	// EVP_PKEY_derive_set_peer()	���L������:���J���Í��R���e�L�X�g ctx �Ɍ��J��� peer (pk_evp)��ݒ肷��D
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
	//		���J���Í��R���e�L�X�g ctx ��p���ċ��L���������s��
	//		�������ꂽ���� secret
	if (EVP_PKEY_derive(ctx, NULL, &secret->len) <= 0 ||
	    (secret->ptr = calloc(1, secret->len)) == NULL ||
	    EVP_PKEY_derive(ctx, secret->ptr, &secret->len) <= 0) {
		log_debug("%s: EVP_PKEY_derive", __func__);
		goto fail;
	}

	/* use sha256 as a kdf on the resulting secret */
	// ���Ő������ꂽsecret��SHA256��ecdh = Shered Secret�ƂȂ�
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
	es256_pk_t *public_key_aG,		// (I )Yubikey����擾�������J��
	es256_pk_t **public_key_bG,		// ( O)�����Ő����������J��(bG)
	fido_blob_t **shearedSecret		// ( O)Sheared Secret
)
{
	es256_sk_t	*private_key_b = NULL; /* our private key */
	int		 r;

	*public_key_bG = NULL; /* our public key; returned */
	*shearedSecret = NULL; /* shared ecdh secret; returned */

	if ((private_key_b = es256_sk_new()) == NULL || (*public_key_bG = es256_pk_new()) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	// sk=�閧��(b)��pk=���J��(bG)�𐶐�
	//  ECDH P-256 key pair
	if (es256_sk_create(private_key_b) < 0 || es256_derive_pk(private_key_b, *public_key_bG) < 0) {
		log_debug("%s: es256_derive_pk", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	// log
	log_debug("---");
	log_debug("%s:�yPrivate Key-b�z �����Ő��������閧��(COSE ES256 (ECDSA over P-256 with SHA-256))", __func__);
	log_xxd(private_key_b->d, 32);
	log_debug("---");
	log_debug("%s:�yPublic Key-bG�z�����Ő����������J��(COSE ES256 (ECDSA over P-256 with SHA-256) public key))", __func__);
	log_debug("x");
	log_xxd((*public_key_bG)->x, 32);
	log_debug("y");
	log_xxd((*public_key_bG)->y, 32);
	log_debug("---");
	log_debug("%s:�yPublic Key-aG�zYubikey�̌��J��(COSE ES256 (ECDSA over P-256 with SHA-256) public key))", __func__);
	log_debug("x");
	log_xxd((public_key_aG)->x, 32);
	log_debug("y");
	log_xxd((public_key_aG)->y, 32);
	log_debug("---");

	// �����Ő��������閧��sk , �擾�������J��ak
	// �����Ƃ� sharedSecret �𐶐�����
	if (do_ecdh(private_key_b, public_key_aG, shearedSecret) < 0) {
		log_debug("%s: do_ecdh", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	log_debug("---");
	log_debug("%s:�yShared Secret�z", __func__);
	log_xxd((*shearedSecret)->ptr, (*shearedSecret)->len);
	log_debug("---");

	r = FIDO_OK;
fail:
	es256_sk_free(&private_key_b);
	if (r != FIDO_OK) {
		es256_pk_free(public_key_bG);
		fido_blob_free(shearedSecret);
	}

	return (r);
}

int
fido_do_ecdh(
		fido_dev_t *dev,
		es256_pk_t **public_key_bG,		// ( O)�����Ő����������J��(bG)
		fido_blob_t **shearedSecret		// ( O)Sheared Secret
		)
{
	es256_pk_t	*public_key_aG = NULL; /* authenticator's public key */
	int		 r;

	// ������getKeyAgreement�R�}���h���M���ĉ����𓾂�
	// ak�ϐ���KeyAgreement(���J��aG)
	if ((public_key_aG = es256_pk_new()) == NULL) {
		log_debug("%s: fido_dev_authkey", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if(fido_dev_authkey(dev, public_key_aG) != FIDO_OK) {
		log_debug("%s: fido_dev_authkey", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}


	if (fido_createSharedSecret(
		public_key_aG,
		public_key_bG,
		shearedSecret) != FIDO_OK) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	r = FIDO_OK;
fail:
	es256_pk_free(&public_key_aG);
	return (r);
}

/*
int
fido_do_ecdh(
	fido_dev_t *dev,
	es256_pk_t **public_key_bG,		// ( O)�����Ő����������J��(bG)
	fido_blob_t **shearedSecret		// ( O)Sheared Secret
)
{

	es256_sk_t	*private_key_b = NULL; // our private key
	es256_pk_t	*public_key_aG = NULL; // authenticator's public key
	int		 r;

	// ������getKeyAgreement�R�}���h���M���ĉ����𓾂�
	// ak�ϐ���KeyAgreement(���J��aG)
	if ((public_key_aG = es256_pk_new()) == NULL) {
		log_debug("%s: fido_dev_authkey", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if (fido_dev_authkey(dev, public_key_aG) != FIDO_OK) {
		log_debug("%s: fido_dev_authkey", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	*public_key_bG = NULL; // our public key; returned
	*shearedSecret = NULL; // shared ecdh secret; returned

	if ((private_key_b = es256_sk_new()) == NULL || (*public_key_bG = es256_pk_new()) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	// sk=�閧��(b)��pk=���J��(bG)�𐶐�
	//  ECDH P-256 key pair
	if (es256_sk_create(private_key_b) < 0 || es256_derive_pk(private_key_b, *public_key_bG) < 0) {
		log_debug("%s: es256_derive_pk", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	// log
	log_debug("---");
	log_debug("%s:�yPrivate Key-b�z �����Ő��������閧��(COSE ES256 (ECDSA over P-256 with SHA-256))", __func__);
	log_xxd(private_key_b->d, 32);
	log_debug("---");
	log_debug("%s:�yPublic Key-bG�z�����Ő����������J��(COSE ES256 (ECDSA over P-256 with SHA-256) public key))", __func__);
	log_debug("x");
	log_xxd((*public_key_bG)->x, 32);
	log_debug("y");
	log_xxd((*public_key_bG)->y, 32);
	log_debug("---");
	log_debug("%s:�yPublic Key-aG�zYubikey�̌��J��(COSE ES256 (ECDSA over P-256 with SHA-256) public key))", __func__);
	log_debug("x");
	log_xxd((public_key_aG)->x, 32);
	log_debug("y");
	log_xxd((public_key_aG)->y, 32);
	log_debug("---");

	// �����Ő��������閧��sk , �擾�������J��ak
	// �����Ƃ� sharedSecret �𐶐�����
	if (do_ecdh(private_key_b, public_key_aG, shearedSecret) < 0) {
		log_debug("%s: do_ecdh", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	log_debug("---");
	log_debug("%s:�yShared Secret�z", __func__);
	log_xxd((*shearedSecret)->ptr, (*shearedSecret)->len);
	log_debug("---");

	r = FIDO_OK;
fail:
	es256_sk_free(&private_key_b);
	es256_pk_free(&public_key_aG);

	if (r != FIDO_OK) {
		es256_pk_free(public_key_bG);
		fido_blob_free(shearedSecret);
	}

	return (r);
}
*/
