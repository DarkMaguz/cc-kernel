/*
 ============================================================================
 Name			: crypto_core.h
 Created			: 03/04/2012
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

#ifndef CRYPTO_CORE_H_
#define CRYPTO_CORE_H_

#include <linux/types.h>
#include <linux/crypto.h>

#define CC_MIN_KEY_SIZE 8
#define CC_MAX_KEY_SIZE 64
#define CC_KEY_SIZE 256
#define CC_BLOCK_SIZE 16

struct cc_ctx
{
	u8 key_enc[CC_KEY_SIZE];
	u8 key_dec[CC_KEY_SIZE];
};

u8 cc_data_at( u8 *data, u8 at );
void cc_build_key( u8 *out_key, const u8 *in_key, u32 in_key_len );
int cc_set_key( struct crypto_tfm *tfm, const u8 *key, unsigned int key_len );

#endif /* CRYPTO_CORE_H_ */
