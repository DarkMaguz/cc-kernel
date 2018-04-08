/*
 ============================================================================
 Name			: crypto_core.cpp
 Created			: 31/03/2012
 Author			: Peter Balling
 Version			: 1.0
 Description	: Physics tool/library
 Copyright		: (C) 2012 Peter Balling
 
 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2 of the License, or (at your option) any later version.
 
 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.
 
 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 
 ============================================================================
 */

#include "crypto_core.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <asm/byteorder.h>

u8 cc_data_at( u8 *data, u8 at )
{
	
	u32 i;
	
	for ( i = 0; i <= at; i++ )
		if ( data[i] == -1 )
			at++;
	
	return at;
	
}
EXPORT_SYMBOL_GPL( cc_data_at );

void cc_build_key( u8 *out_key, const u8 *in_key, u32 in_key_len )
{
	
	u8 data[CC_KEY_SIZE] =
	{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,	30, 31, 32,
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
		63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92,
		93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
		118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
		141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163,
		164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186,
		187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
		210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232,
		233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
	};
	u32 i;
	u8 at;
	
	for ( i = 0; i < CC_KEY_SIZE; i++ )
	{
		
		at = cc_data_at( data, ( in_key[i % in_key_len ] * ( ( i / in_key_len ) + 1 ) ) % ( CC_KEY_SIZE - i ) );
		
		out_key[i] = data[at];
		
		data[at] = -1;
		
	}
	
}
EXPORT_SYMBOL_GPL( cc_build_key );

int cc_set_key( struct crypto_tfm *tfm, const u8 *key, unsigned int key_len )
{
	
	struct cc_ctx *ctx = crypto_tfm_ctx( tfm );
	u32 *flags = &tfm->crt_flags;
	u32 i;
	
	if ( key_len < CC_MIN_KEY_SIZE || key_len > CC_MAX_KEY_SIZE )
	{
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}
	
	cc_build_key( ctx->key_enc, key, key_len );
	
	for ( i = 0; i < CC_KEY_SIZE; i++ )
	{
		ctx->key_dec[ctx->key_enc[i]] = i;
	}
	
	return 0;
	
}
EXPORT_SYMBOL_GPL( cc_set_key );

static void cc_encrypt( struct crypto_tfm *tfm, u8 *out, const u8 *in )
{
	
	struct cc_ctx *ctx = crypto_tfm_ctx( tfm );
	u32 i;
	
	for ( i = 0; i < CC_BLOCK_SIZE; i++ )
	{
		out[i] = ctx->key_enc[in[i]];
	}
	
}

static void cc_decrypt( struct crypto_tfm *tfm, u8 *out, const u8 *in )
{
	
	struct cc_ctx *ctx = crypto_tfm_ctx( tfm );
	u32 i;
	
	for ( i = 0; i < CC_BLOCK_SIZE; i++ )
	{
		out[i] = ctx->key_dec[in[i]];
	}
	
}

static struct crypto_alg cc_alg =
{
	.cra_name = "cc",
	.cra_driver_name = "crypto-core",
	.cra_priority = 100,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize = CC_BLOCK_SIZE,
	.cra_ctxsize = sizeof( struct cc_ctx ),
	.cra_alignmask = 3,
	.cra_module = THIS_MODULE,
	.cra_list = LIST_HEAD_INIT( cc_alg.cra_list ),
	.cra_u	 =
	{
		.cipher =
		{
			.cia_min_keysize = CC_MIN_KEY_SIZE,
			.cia_max_keysize = CC_MAX_KEY_SIZE,
			.cia_setkey = cc_set_key,
			.cia_encrypt = cc_encrypt,
			.cia_decrypt = cc_decrypt
		}
	}
};

static int __init cc_init( void )
{
	return crypto_register_alg( &cc_alg );
}

static void __exit cc_fini( void )
{
	crypto_unregister_alg( &cc_alg );
}

module_init( cc_init );
module_exit( cc_fini );

MODULE_DESCRIPTION( "Balling (cc) Cipher Algorithm" );
MODULE_LICENSE( "GPL" );
MODULE_ALIAS( "cc" );
