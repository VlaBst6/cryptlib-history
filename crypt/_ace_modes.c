#define via_cwd( a, b, c, d )	// Hack
void *cwd;

/*
 ---------------------------------------------------------------------------
 Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue 31/01/2006

 These subroutines implement multiple block AES modes for ECB, CBC, CFB,
 OFB and CTR encryption,  The code provides support for the VIA Advanced
 Cryptography Engine (ACE).

 NOTE: In the following subroutines, the AES contexts (ctx) must be
 16 byte aligned if VIA ACE is being used
*/

#include <string.h>
#include <assert.h>

#include "crypt/aesopt.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#if defined( _MSC_VER ) && ( _MSC_VER > 800 )
#pragma intrinsic(memcpy)
#define in_line __inline
#else
#define in_line
#endif

#define BFR_BLOCKS      8

/* These values are used to detect long word alignment in order */
/* to speed up some buffer operations.                          */

#pragma warning( disable : 4311 4312 )

#define lp08(x)         ((uint_8t*)(x))
#define lp32(x)         ((uint_32t*)(x))
#define addr_mod_04(x) ((unsigned long)(x) & 3)

#if defined( USE_VIA_ACE_IF_PRESENT )	/* pcg */
  #include "crypt/via_ace.h"
#endif /* USE_VIA_ACE_IF_PRESENT */

#define addr_mod_16(x)    ((unsigned long)(x) & 15)

#if defined( USE_VIA_ACE_IF_PRESENT )	/* pcg */
  #if NEH_KEY_TYPE == NEH_LOAD
	#define kd_adr(c)   ((uint_8t*)(c)->ks)
  #elif NEH_KEY_TYPE == NEH_GENERATE
	#define kd_adr(c)   ((uint_8t*)(c)->ks + (c)->inf.b[0])
  #else
	#define kd_adr(c)   ((uint_8t*)(c)->ks + ((c)->inf.b[0] == 160 ? 160 : 0))
  #endif
#else
  #define kd_adr(c)   ((uint_8t*)(c)->ks + ((c)->inf.b[0] == 160 ? 160 : 0))
#endif /* USE_VIA_ACE_IF_PRESENT */

aes_rval aes_mode_reset(aes_encrypt_ctx ctx[1])
{
    ctx->inf.b[2] = 0;
    return EXIT_SUCCESS;
}

aes_rval aes_ecb_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, const aes_encrypt_ctx ctx[1])
{   int nb = len >> 4;

    if(len & (AES_BLOCK_SIZE - 1))
        return EXIT_FAILURE;

#if defined( USE_VIA_ACE_IF_PRESENT )

    if(ctx->inf.b[1] == 0xff)
    {   uint_8t *ksp = (uint_8t*)(ctx->ks);
		via_cwd(cwd, hybrid, enc, 2* ctx->inf.b[0] - 192);

        if(addr_mod_16(ctx))
            return EXIT_FAILURE;

        if(!addr_mod_16(ibuf) && !addr_mod_16(obuf))
        {
            via_ecb_op5(ksp,cwd,ibuf,obuf,nb);
        }
        else
        {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
            uint_8t *ip, *op;

            while(nb)
            {
                int m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb);

                ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                op = (addr_mod_16(obuf) ? buf : obuf);

                if(ip != ibuf)
                    memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                via_ecb_op5(ksp,cwd,ip,op,m);

                if(op != obuf)
                    memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                ibuf += m * AES_BLOCK_SIZE;
                obuf += m * AES_BLOCK_SIZE;
                nb -= m;
            }
        }

        return EXIT_SUCCESS;
    }

#endif

#if !defined( ASSUME_VIA_ACE_PRESENT )
    while(nb--)
    {
        aes_encrypt(ibuf, obuf, ctx);
        ibuf += AES_BLOCK_SIZE;
        obuf += AES_BLOCK_SIZE;
    }
#endif
    return EXIT_SUCCESS;
}

aes_rval aes_ecb_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, const aes_decrypt_ctx ctx[1])
{   int nb = len >> 4;

    if(len & (AES_BLOCK_SIZE - 1))
        return EXIT_FAILURE;

#if defined( USE_VIA_ACE_IF_PRESENT )

    if(ctx->inf.b[1] == 0xff)
	{   uint_8t *ksp = kd_adr(ctx);
		via_cwd(cwd, hybrid, dec, 2* ctx->inf.b[0] - 192);

        if(addr_mod_16(ctx))
            return EXIT_FAILURE;

        if(!addr_mod_16(ibuf) && !addr_mod_16(obuf))
        {
            via_ecb_op5(ksp,cwd,ibuf,obuf,nb);
        }
        else
        {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
            uint_8t *ip, *op;

            while(nb)
            {
                int m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb);

                ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                op = (addr_mod_16(obuf) ? buf : obuf);

                if(ip != ibuf)
                    memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                via_ecb_op5(ksp,cwd,ip,op,m);

                if(op != obuf)
                    memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                ibuf += m * AES_BLOCK_SIZE;
                obuf += m * AES_BLOCK_SIZE;
                nb -= m;
            }
        }

        return EXIT_SUCCESS;
    }

#endif

#if !defined( ASSUME_VIA_ACE_PRESENT )
    while(nb--)
    {
        aes_decrypt(ibuf, obuf, ctx);
        ibuf += AES_BLOCK_SIZE;
        obuf += AES_BLOCK_SIZE;
    }
#endif
    return EXIT_SUCCESS;
}

aes_rval aes_cbc_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, const aes_encrypt_ctx ctx[1])
{   int nb = len >> 4;

    if(len & (AES_BLOCK_SIZE - 1))
        return EXIT_FAILURE;

#if defined( USE_VIA_ACE_IF_PRESENT )

    if(ctx->inf.b[1] == 0xff)
    {   uint_8t *ksp = (uint_8t*)(ctx->ks), *ivp = iv;
        aligned_auto(uint_8t, liv, AES_BLOCK_SIZE, 16);
		via_cwd(cwd, hybrid, enc, 2* ctx->inf.b[0] - 192);

        if(addr_mod_16(ctx))
            return EXIT_FAILURE;

        if(addr_mod_16(iv))   /* ensure an aligned iv */
        {
            ivp = liv;
            memcpy(liv, iv, AES_BLOCK_SIZE);
        }

        if(!addr_mod_16(ibuf) && !addr_mod_16(obuf) && !addr_mod_16(iv))
        {
            via_cbc_op7(ksp,cwd,ibuf,obuf,nb,ivp,ivp);
        }
        else
        {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
            uint_8t *ip, *op;

            while(nb)
            {
                int m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb);

                ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                op = (addr_mod_16(obuf) ? buf : obuf);

                if(ip != ibuf)
                    memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                via_cbc_op7(ksp,cwd,ip,op,m,ivp,ivp);

                if(op != obuf)
                    memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                ibuf += m * AES_BLOCK_SIZE;
                obuf += m * AES_BLOCK_SIZE;
                nb -= m;
            }
        }

        if(iv != ivp)
            memcpy(iv, ivp, AES_BLOCK_SIZE);

        return EXIT_SUCCESS;
    }

#endif

#if !defined( ASSUME_VIA_ACE_PRESENT )
    if(!addr_mod_04(ibuf) && !addr_mod_04(iv))
        while(nb--)
        {
            lp32(iv)[0] ^= lp32(ibuf)[0];
            lp32(iv)[1] ^= lp32(ibuf)[1];
            lp32(iv)[2] ^= lp32(ibuf)[2];
            lp32(iv)[3] ^= lp32(ibuf)[3];
            aes_encrypt(iv, iv, ctx);
            memcpy(obuf, iv, AES_BLOCK_SIZE);
            ibuf += AES_BLOCK_SIZE;
            obuf += AES_BLOCK_SIZE;
        }
    else
        while(nb--)
        {
            iv[ 0] ^= ibuf[ 0]; iv[ 1] ^= ibuf[ 1];
            iv[ 2] ^= ibuf[ 2]; iv[ 3] ^= ibuf[ 3];
            iv[ 4] ^= ibuf[ 4]; iv[ 5] ^= ibuf[ 5];
            iv[ 6] ^= ibuf[ 6]; iv[ 7] ^= ibuf[ 7];
            iv[ 8] ^= ibuf[ 8]; iv[ 9] ^= ibuf[ 9];
            iv[10] ^= ibuf[10]; iv[11] ^= ibuf[11];
            iv[12] ^= ibuf[12]; iv[13] ^= ibuf[13];
            iv[14] ^= ibuf[14]; iv[15] ^= ibuf[15];
            aes_encrypt(iv, iv, ctx);
            memcpy(obuf, iv, AES_BLOCK_SIZE);
            ibuf += AES_BLOCK_SIZE;
            obuf += AES_BLOCK_SIZE;
        }
#endif
    return EXIT_SUCCESS;
}

aes_rval aes_cbc_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, const aes_decrypt_ctx ctx[1])
{   unsigned char tmp[AES_BLOCK_SIZE];
    int nb = len >> 4;

    if(len & (AES_BLOCK_SIZE - 1))
        return EXIT_FAILURE;

#if defined( USE_VIA_ACE_IF_PRESENT )

    if(ctx->inf.b[1] == 0xff)
    {   uint_8t *ksp = kd_adr(ctx), *ivp = iv;
        aligned_auto(uint_8t, liv, AES_BLOCK_SIZE, 16);
		via_cwd(cwd, hybrid, dec, 2* ctx->inf.b[0] - 192);

        if(addr_mod_16(ctx))
            return EXIT_FAILURE;

        if(addr_mod_16(iv))   /* ensure an aligned iv */
        {
            ivp = liv;
            memcpy(liv, iv, AES_BLOCK_SIZE);
        }

        if(!addr_mod_16(ibuf) && !addr_mod_16(obuf) && !addr_mod_16(iv))
        {
            via_cbc_op6(ksp,cwd,ibuf,obuf,nb,ivp);
        }
        else
        {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
            uint_8t *ip, *op;

            while(nb)
            {
                int m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb);

                ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                op = (addr_mod_16(obuf) ? buf : obuf);

                if(ip != ibuf)
                    memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                via_cbc_op6(ksp,cwd,ip,op,m,ivp);

                if(op != obuf)
                    memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                ibuf += m * AES_BLOCK_SIZE;
                obuf += m * AES_BLOCK_SIZE;
                nb -= m;
            }
        }

        if(iv != ivp)
            memcpy(iv, ivp, AES_BLOCK_SIZE);

        return EXIT_SUCCESS;
    }
#endif

#if !defined( ASSUME_VIA_ACE_PRESENT )
    if(!addr_mod_04(obuf) && !addr_mod_04(iv))
        while(nb--)
        {
            memcpy(tmp, ibuf, AES_BLOCK_SIZE);
            aes_decrypt(ibuf, obuf, ctx);
            lp32(obuf)[0] ^= lp32(iv)[0];
            lp32(obuf)[1] ^= lp32(iv)[1];
            lp32(obuf)[2] ^= lp32(iv)[2];
            lp32(obuf)[3] ^= lp32(iv)[3];
            memcpy(iv, tmp, AES_BLOCK_SIZE);
            ibuf += AES_BLOCK_SIZE;
            obuf += AES_BLOCK_SIZE;
        }
    else
        while(nb--)
        {
            memcpy(tmp, ibuf, AES_BLOCK_SIZE);
            aes_decrypt(ibuf, obuf, ctx);
            obuf[ 0] ^= iv[ 0]; obuf[ 1] ^= iv[ 1];
            obuf[ 2] ^= iv[ 2]; obuf[ 3] ^= iv[ 3];
            obuf[ 4] ^= iv[ 4]; obuf[ 5] ^= iv[ 5];
            obuf[ 6] ^= iv[ 6]; obuf[ 7] ^= iv[ 7];
            obuf[ 8] ^= iv[ 8]; obuf[ 9] ^= iv[ 9];
            obuf[10] ^= iv[10]; obuf[11] ^= iv[11];
            obuf[12] ^= iv[12]; obuf[13] ^= iv[13];
            obuf[14] ^= iv[14]; obuf[15] ^= iv[15];
            memcpy(iv, tmp, AES_BLOCK_SIZE);
            ibuf += AES_BLOCK_SIZE;
            obuf += AES_BLOCK_SIZE;
        }
#endif
    return EXIT_SUCCESS;
}

aes_rval aes_cfb_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, aes_encrypt_ctx ctx[1])
{   int cnt = 0, b_pos = (int)ctx->inf.b[2], nb;

    if(b_pos)           /* complete any partial block   */
    {
        while(b_pos < AES_BLOCK_SIZE && cnt < len)
            *obuf++ = iv[b_pos++] ^= *ibuf++, cnt++;

        b_pos = (b_pos == AES_BLOCK_SIZE ? 0 : b_pos);
    }

    if((nb = (len - cnt) >> 4) != 0)	/* process whole blocks */
    {
#if defined( USE_VIA_ACE_IF_PRESENT )

        if(ctx->inf.b[1] == 0xff)
        {   int m;
			uint_8t *ksp = (uint_8t*)(ctx->ks), *ivp = iv;
            aligned_auto(uint_8t, liv, AES_BLOCK_SIZE, 16);
			via_cwd(cwd, hybrid, enc, 2* ctx->inf.b[0] - 192);

        if(addr_mod_16(ctx))
            return EXIT_FAILURE;

            if(addr_mod_16(iv))   /* ensure an aligned iv */
            {
                ivp = liv;
                memcpy(liv, iv, AES_BLOCK_SIZE);
            }

            if(!addr_mod_16(ibuf) && !addr_mod_16(obuf))
            {
                via_cfb_op7(ksp, cwd, ibuf, obuf, nb, ivp, ivp);
                ibuf += nb * AES_BLOCK_SIZE;
                obuf += nb * AES_BLOCK_SIZE;
                cnt  += nb * AES_BLOCK_SIZE;
            }
            else    /* input, output or both are unaligned  */
            {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
                uint_8t *ip, *op;

                while(nb)
                {
                    m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb), nb -= m;

                    ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                    op = (addr_mod_16(obuf) ? buf : obuf);

                    if(ip != ibuf)
                        memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                    via_cfb_op7(ksp, cwd, ip, op, m, ivp, ivp);

                    if(op != obuf)
                        memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                    ibuf += m * AES_BLOCK_SIZE;
                    obuf += m * AES_BLOCK_SIZE;
                    cnt  += m * AES_BLOCK_SIZE;
                }
            }

            if(ivp != iv)
                memcpy(iv, ivp, AES_BLOCK_SIZE);
        }
#else
        if(!addr_mod_04(ibuf) && !addr_mod_04(obuf) && !addr_mod_04(iv))
            while(cnt + AES_BLOCK_SIZE <= len)
            {
                assert(b_pos == 0);
                aes_encrypt(iv, iv, ctx);
                lp32(obuf)[0] = lp32(iv)[0] ^= lp32(ibuf)[0];
                lp32(obuf)[1] = lp32(iv)[1] ^= lp32(ibuf)[1];
                lp32(obuf)[2] = lp32(iv)[2] ^= lp32(ibuf)[2];
                lp32(obuf)[3] = lp32(iv)[3] ^= lp32(ibuf)[3];
                ibuf += AES_BLOCK_SIZE;
                obuf += AES_BLOCK_SIZE;
                cnt  += AES_BLOCK_SIZE;
            }
        else
            while(cnt + AES_BLOCK_SIZE <= len)
            {
                assert(b_pos == 0);
                aes_encrypt(iv, iv, ctx);
                obuf[ 0] = iv[ 0] ^= ibuf[ 0]; obuf[ 1] = iv[ 1] ^= ibuf[ 1];
                obuf[ 2] = iv[ 2] ^= ibuf[ 2]; obuf[ 3] = iv[ 3] ^= ibuf[ 3];
                obuf[ 4] = iv[ 4] ^= ibuf[ 4]; obuf[ 5] = iv[ 5] ^= ibuf[ 5];
                obuf[ 6] = iv[ 6] ^= ibuf[ 6]; obuf[ 7] = iv[ 7] ^= ibuf[ 7];
                obuf[ 8] = iv[ 8] ^= ibuf[ 8]; obuf[ 9] = iv[ 9] ^= ibuf[ 9];
                obuf[10] = iv[10] ^= ibuf[10]; obuf[11] = iv[11] ^= ibuf[11];
                obuf[12] = iv[12] ^= ibuf[12]; obuf[13] = iv[13] ^= ibuf[13];
                obuf[14] = iv[14] ^= ibuf[14]; obuf[15] = iv[15] ^= ibuf[15];
                ibuf += AES_BLOCK_SIZE;
                obuf += AES_BLOCK_SIZE;
                cnt  += AES_BLOCK_SIZE;
            }
#endif
    }

    while(cnt < len)
    {
        if(!b_pos)
            aes_ecb_encrypt(iv, iv, AES_BLOCK_SIZE, ctx);

        while(cnt < len && b_pos < AES_BLOCK_SIZE)
            *obuf++ = iv[b_pos++] ^= *ibuf++, cnt++;

        b_pos = (b_pos == AES_BLOCK_SIZE ? 0 : b_pos);
    }

    ctx->inf.b[2] = b_pos;
    return EXIT_SUCCESS;
}

aes_rval aes_cfb_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, aes_encrypt_ctx ctx[1])
{   int cnt = 0, b_pos = (int)ctx->inf.b[2], nb;

    if(b_pos)           /* complete any partial block   */
    {   uint_8t t;

        while(b_pos < AES_BLOCK_SIZE && cnt < len)
            t = *ibuf++, *obuf++ = t ^ iv[b_pos], iv[b_pos++] = t, cnt++;

        b_pos = (b_pos == AES_BLOCK_SIZE ? 0 : b_pos);
    }

    if((nb = (len - cnt) >> 4) != 0)	/* process whole blocks */
    {
#if defined( USE_VIA_ACE_IF_PRESENT )

        if(ctx->inf.b[1] == 0xff)
        {   int m;
			uint_8t *ksp = (uint_8t*)(ctx->ks), *ivp = iv;
            aligned_auto(uint_8t, liv, AES_BLOCK_SIZE, 16);
            via_cwd(cwd, hybrid, dec, 2* ctx->inf.b[0] - 192);

        if(addr_mod_16(ctx))
            return EXIT_FAILURE;

            if(addr_mod_16(iv))   /* ensure an aligned iv */
            {
                ivp = liv;
                memcpy(liv, iv, AES_BLOCK_SIZE);
            }

            if(!addr_mod_16(ibuf) && !addr_mod_16(obuf))
            {
                via_cfb_op6(ksp, cwd, ibuf, obuf, nb, ivp);
                ibuf += nb * AES_BLOCK_SIZE;
                obuf += nb * AES_BLOCK_SIZE;
                cnt  += nb * AES_BLOCK_SIZE;
            }
            else    /* input, output or both are unaligned  */
            {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
                uint_8t *ip, *op;

                while(nb)
                {
                    m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb), nb -= m;

                    ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                    op = (addr_mod_16(obuf) ? buf : op);

                    if(ip != ibuf)
                        memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                    via_cfb_op6(ksp, cwd, ip, op, m, ivp);

                    if(op != obuf)
                        memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                    ibuf += m * AES_BLOCK_SIZE;
                    obuf += m * AES_BLOCK_SIZE;
                    cnt  += m * AES_BLOCK_SIZE;
                }
            }

            if(ivp != iv)
                memcpy(iv, ivp, AES_BLOCK_SIZE);
        }
#else
        if(!addr_mod_04(ibuf) && !addr_mod_04(obuf) &&!addr_mod_04(iv))
            while(cnt + AES_BLOCK_SIZE <= len)
            {   uint_32t t;

                assert(b_pos == 0);
                aes_encrypt(iv, iv, ctx);
                t = lp32(ibuf)[0], lp32(obuf)[0] = t ^ lp32(iv)[0], lp32(iv)[0] = t;
                t = lp32(ibuf)[1], lp32(obuf)[1] = t ^ lp32(iv)[1], lp32(iv)[1] = t;
                t = lp32(ibuf)[2], lp32(obuf)[2] = t ^ lp32(iv)[2], lp32(iv)[2] = t;
                t = lp32(ibuf)[3], lp32(obuf)[3] = t ^ lp32(iv)[3], lp32(iv)[3] = t;
                ibuf += AES_BLOCK_SIZE;
                obuf += AES_BLOCK_SIZE;
                cnt  += AES_BLOCK_SIZE;
            }
        else
            while(cnt + AES_BLOCK_SIZE <= len)
            {   uint_8t t;

                assert(b_pos == 0);
                aes_encrypt(iv, iv, ctx);
                t = ibuf[ 0], obuf[ 0] = t ^ iv[ 0], iv[ 0] = t;
                t = ibuf[ 1], obuf[ 1] = t ^ iv[ 1], iv[ 1] = t;
                t = ibuf[ 2], obuf[ 2] = t ^ iv[ 2], iv[ 2] = t;
                t = ibuf[ 3], obuf[ 3] = t ^ iv[ 3], iv[ 3] = t;
                t = ibuf[ 4], obuf[ 4] = t ^ iv[ 4], iv[ 4] = t;
                t = ibuf[ 5], obuf[ 5] = t ^ iv[ 5], iv[ 5] = t;
                t = ibuf[ 6], obuf[ 6] = t ^ iv[ 6], iv[ 6] = t;
                t = ibuf[ 7], obuf[ 7] = t ^ iv[ 7], iv[ 7] = t;
                t = ibuf[ 8], obuf[ 8] = t ^ iv[ 8], iv[ 8] = t;
                t = ibuf[ 9], obuf[ 9] = t ^ iv[ 9], iv[ 9] = t;
                t = ibuf[10], obuf[10] = t ^ iv[10], iv[10] = t;
                t = ibuf[11], obuf[11] = t ^ iv[11], iv[11] = t;
                t = ibuf[12], obuf[12] = t ^ iv[12], iv[12] = t;
                t = ibuf[13], obuf[13] = t ^ iv[13], iv[13] = t;
                t = ibuf[14], obuf[14] = t ^ iv[14], iv[14] = t;
                t = ibuf[15], obuf[15] = t ^ iv[15], iv[15] = t;
                ibuf += AES_BLOCK_SIZE;
                obuf += AES_BLOCK_SIZE;
                cnt  += AES_BLOCK_SIZE;
            }
#endif
    }

    while(cnt < len)
    {   uint_8t t;

        if(!b_pos)
            aes_ecb_encrypt(iv, iv, AES_BLOCK_SIZE, ctx);

        while(cnt < len && b_pos < AES_BLOCK_SIZE)
            t = *ibuf++, *obuf++ = t ^ iv[b_pos], iv[b_pos++] = t, cnt++;

        b_pos = (b_pos == AES_BLOCK_SIZE ? 0 : b_pos);
    }

    ctx->inf.b[2] = b_pos;
    return EXIT_SUCCESS;
}

aes_rval aes_ofb_crypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, aes_encrypt_ctx ctx[1])
{   int cnt = 0, b_pos = (int)ctx->inf.b[2], nb;

    if(b_pos)           /* complete any partial block   */
    {
        while(b_pos < AES_BLOCK_SIZE && cnt < len)
            *obuf++ = iv[b_pos++] ^ *ibuf++, cnt++;

        b_pos = (b_pos == AES_BLOCK_SIZE ? 0 : b_pos);
    }

    if((nb = (len - cnt) >> 4) != 0)   /* process whole blocks */
    {
#if defined( USE_VIA_ACE_IF_PRESENT )

        if(ctx->inf.b[1] == 0xff)
        {   int m;
			uint_8t *ksp = (uint_8t*)(ctx->ks), *ivp = iv;
            aligned_auto(uint_8t, liv, AES_BLOCK_SIZE, 16);
            via_cwd(cwd, hybrid, enc, 2* ctx->inf.b[0] - 192);

        if(addr_mod_16(ctx))
            return EXIT_FAILURE;

            if(addr_mod_16(iv))   /* ensure an aligned iv */
            {
                ivp = liv;
                memcpy(liv, iv, AES_BLOCK_SIZE);
            }

            if(!addr_mod_16(ibuf) && !addr_mod_16(obuf))
            {
                via_ofb_op6(ksp, cwd, ibuf, obuf, nb, ivp);
                ibuf += nb * AES_BLOCK_SIZE;
                obuf += nb * AES_BLOCK_SIZE;
                cnt  += nb * AES_BLOCK_SIZE;
            }
            else    /* input, output or both are unaligned  */
        {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
            uint_8t *ip, *op;

                while(nb)
                {
                    m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb), nb -= m;

                    ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                    op = (addr_mod_16(obuf) ? buf : obuf);

                    if(ip != ibuf)
                        memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                    via_ofb_op6(ksp, cwd, ip, op, m, ivp);

                    if(op != obuf)
                        memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                    ibuf += m * AES_BLOCK_SIZE;
                    obuf += m * AES_BLOCK_SIZE;
                    cnt  += m * AES_BLOCK_SIZE;
                }
            }

            if(ivp != iv)
                memcpy(iv, ivp, AES_BLOCK_SIZE);
        }
#else
        if(!addr_mod_04(ibuf) && !addr_mod_04(obuf) && !addr_mod_04(iv))
            while(cnt + AES_BLOCK_SIZE <= len)
            {
                assert(b_pos == 0);
                aes_encrypt(iv, iv, ctx);
                lp32(obuf)[0] = lp32(iv)[0] ^ lp32(ibuf)[0];
                lp32(obuf)[1] = lp32(iv)[1] ^ lp32(ibuf)[1];
                lp32(obuf)[2] = lp32(iv)[2] ^ lp32(ibuf)[2];
                lp32(obuf)[3] = lp32(iv)[3] ^ lp32(ibuf)[3];
                ibuf += AES_BLOCK_SIZE;
                obuf += AES_BLOCK_SIZE;
                cnt  += AES_BLOCK_SIZE;
            }
        else
            while(cnt + AES_BLOCK_SIZE <= len)
            {
                assert(b_pos == 0);
                aes_encrypt(iv, iv, ctx);
                obuf[ 0] = iv[ 0] ^ ibuf[ 0]; obuf[ 1] = iv[ 1] ^ ibuf[ 1];
                obuf[ 2] = iv[ 2] ^ ibuf[ 2]; obuf[ 3] = iv[ 3] ^ ibuf[ 3];
                obuf[ 4] = iv[ 4] ^ ibuf[ 4]; obuf[ 5] = iv[ 5] ^ ibuf[ 5];
                obuf[ 6] = iv[ 6] ^ ibuf[ 6]; obuf[ 7] = iv[ 7] ^ ibuf[ 7];
                obuf[ 8] = iv[ 8] ^ ibuf[ 8]; obuf[ 9] = iv[ 9] ^ ibuf[ 9];
                obuf[10] = iv[10] ^ ibuf[10]; obuf[11] = iv[11] ^ ibuf[11];
                obuf[12] = iv[12] ^ ibuf[12]; obuf[13] = iv[13] ^ ibuf[13];
                obuf[14] = iv[14] ^ ibuf[14]; obuf[15] = iv[15] ^ ibuf[15];
                ibuf += AES_BLOCK_SIZE;
                obuf += AES_BLOCK_SIZE;
                cnt  += AES_BLOCK_SIZE;
            }
#endif
    }

    while(cnt < len)
    {
        if(!b_pos)
            aes_ecb_encrypt(iv, iv, AES_BLOCK_SIZE, ctx);

        while(cnt < len && b_pos < AES_BLOCK_SIZE)
            *obuf++ = iv[b_pos++] ^ *ibuf++, cnt++;

        b_pos = (b_pos == AES_BLOCK_SIZE ? 0 : b_pos);
    }

    ctx->inf.b[2] = b_pos;
    return EXIT_SUCCESS;
}

#define BFR_LENGTH  (BFR_BLOCKS * AES_BLOCK_SIZE)

aes_rval aes_ctr_crypt(const unsigned char *ibuf, unsigned char *obuf,
            int len, unsigned char *cbuf, cbuf_inc ctr_inc, aes_encrypt_ctx ctx[1])
{   uint_8t *ip;
    int     i, blen, b_pos = (int)(ctx->inf.b[2]);

#if defined( USE_VIA_ACE_IF_PRESENT )
    aligned_auto(uint_8t, buf, BFR_LENGTH, 16);
    if(addr_mod_16(ctx))
        return EXIT_FAILURE;
#else
    uint_8t buf[BFR_LENGTH];
#endif

    if(b_pos)
    {
        memcpy(buf, cbuf, AES_BLOCK_SIZE);
        aes_ecb_encrypt(buf, buf, AES_BLOCK_SIZE, ctx);
        while(b_pos < AES_BLOCK_SIZE && len--)
            *obuf++ = *ibuf++ ^ buf[b_pos++];
        if(len)
            ctr_inc(cbuf), b_pos = 0;
    }

    while(len)
    {
        blen = (len > BFR_LENGTH ? BFR_LENGTH : len), len -= blen;

        for(i = 0, ip = buf; i < (blen >> 4); ++i)
        {
            memcpy(ip, cbuf, AES_BLOCK_SIZE);
            ctr_inc(cbuf);
            ip += AES_BLOCK_SIZE;
        }

        if(blen & (AES_BLOCK_SIZE - 1))
            memcpy(ip, cbuf, AES_BLOCK_SIZE), i++;

#if defined( USE_VIA_ACE_IF_PRESENT )
        if(ctx->inf.b[1] == 0xff)
		{
			via_cwd(cwd, hybrid, enc, 2* ctx->inf.b[0] - 192);
            via_ecb_op5((ctx->ks),cwd,buf,buf,i);
		}
        else
#endif
        aes_ecb_encrypt(buf, buf, i * AES_BLOCK_SIZE, ctx);

        i = 0; ip = buf;
        if(!addr_mod_04(ibuf) && !addr_mod_04(obuf) && !addr_mod_04(ip))
            while(i + AES_BLOCK_SIZE <= blen)
            {
                lp32(obuf)[0] = lp32(ibuf)[0] ^ lp32(ip)[0];
                lp32(obuf)[1] = lp32(ibuf)[1] ^ lp32(ip)[1];
                lp32(obuf)[2] = lp32(ibuf)[2] ^ lp32(ip)[2];
                lp32(obuf)[3] = lp32(ibuf)[3] ^ lp32(ip)[3];
                i += AES_BLOCK_SIZE;
                ip += AES_BLOCK_SIZE;
                ibuf += AES_BLOCK_SIZE;
                obuf += AES_BLOCK_SIZE;
            }
        else
            while(i + AES_BLOCK_SIZE <= blen)
            {
                obuf[ 0] = ibuf[ 0] ^ ip[ 0]; obuf[ 1] = ibuf[ 1] ^ ip[ 1];
                obuf[ 2] = ibuf[ 2] ^ ip[ 2]; obuf[ 3] = ibuf[ 3] ^ ip[ 3];
                obuf[ 4] = ibuf[ 4] ^ ip[ 4]; obuf[ 5] = ibuf[ 5] ^ ip[ 5];
                obuf[ 6] = ibuf[ 6] ^ ip[ 6]; obuf[ 7] = ibuf[ 7] ^ ip[ 7];
                obuf[ 8] = ibuf[ 8] ^ ip[ 8]; obuf[ 9] = ibuf[ 9] ^ ip[ 9];
                obuf[10] = ibuf[10] ^ ip[10]; obuf[11] = ibuf[11] ^ ip[11];
                obuf[12] = ibuf[12] ^ ip[12]; obuf[13] = ibuf[13] ^ ip[13];
                obuf[14] = ibuf[14] ^ ip[14]; obuf[15] = ibuf[15] ^ ip[15];
                i += AES_BLOCK_SIZE;
                ip += AES_BLOCK_SIZE;
                ibuf += AES_BLOCK_SIZE;
                obuf += AES_BLOCK_SIZE;
            }

        while(i++ < blen)
            *obuf++ = *ibuf++ ^ ip[b_pos++];
    }

    ctx->inf.b[2] = b_pos;
    return EXIT_SUCCESS;
}

#if defined(__cplusplus)
}
#endif