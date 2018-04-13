/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  */
#pragma once

#include "cryptonight.h"
#include "xmrstak/backend/cryptonight.hpp"
#include "soft_aes.hpp"
#include <memory.h>
#include <stdio.h>
#include <altivec.h>
#undef vector
#undef pixel
#undef bool
typedef __vector unsigned char __m128i;
typedef __vector unsigned long long __m128ll;

static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
  uint64_t lo;
  asm( 
    "mulld  %0, %1, %2" :  
    "=r" (lo) : 
    "r" (a), 
    "r" (b)); 
  asm(
    "mulhdu %0, %1, %2" : 
    "=r" (*hi) : 
    "r" (a), 
    "r" (b));
  return lo;
}

extern "C"
{
	void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);
	void keccakf(uint64_t st[25], int rounds);
	extern void(*const extra_hashes[4])(const void *, size_t, char *);
   
}

static inline __m128i _mm_set_epi64x(uint64_t a, uint64_t b){
  return (__m128ll){b,a};
}
// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
  __m128i tmp4;
  tmp4 = vec_slo(tmp1, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  tmp4 = vec_slo(tmp4, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  tmp4 = vec_slo(tmp4, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  return tmp1;
}

static inline __m128i sl_xor_be(__m128i tmp1)
{
  __m128i tmp4;
  tmp4 = vec_sro(tmp1, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  tmp4 = vec_sro(tmp4, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  tmp4 = vec_sro(tmp4, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  return tmp1;
}
static inline __m128i v_rev(const __m128i& tmp1)
{
  return(vec_perm(tmp1,tmp1,(__m128i){ 0xf,0xe,0xd,0xc,0xb,0xa,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0 })); 
}


static inline __m128i _mm_aesenc_si128(__m128i in, __m128i key)
{
  return v_rev(__builtin_crypto_vcipher(v_rev(in),v_rev(key)));
}

static inline __m128i _mm_aesenc_si128_beIN(__m128i in, __m128i key)
{
  return v_rev(__builtin_crypto_vcipher(in,v_rev(key)));
}

static inline __m128i _mm_aesenc_si128_beK(__m128i in, __m128i key)
{
  return v_rev(__builtin_crypto_vcipher(v_rev(in),key));
}
static inline __m128i _mm_aesenc_si128_be(__m128i in, __m128i key)
{
  return __builtin_crypto_vcipher(in,key);
}


template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
  __m128i xout1 = soft_aeskeygenassist(*xout2, rcon);
  xout1 = vec_perm(xout1,xout1,(__m128i){0xc,0xd,0xe,0xf, 0xc,0xd,0xe,0xf, 0xc,0xd,0xe,0xf, 0xc,0xd,0xe,0xf}); 
  *xout0 = sl_xor(*xout0);
  *xout0 = vec_xor(*xout0, xout1);
  xout1 = soft_aeskeygenassist(*xout0, 0x00);
  xout1 = vec_perm(xout1,xout1,(__m128i){0x8,0x9,0xa,0xb, 0x8,0x9,0xa,0xb, 0x8,0x9,0xa,0xb, 0x8,0x9,0xa,0xb});
  *xout2 = sl_xor(*xout2);
  *xout2 = vec_xor(*xout2, xout1);
}

template<uint8_t rcon>
static inline void aes_genkey_sub_be(__m128i* xout0, __m128i* xout2)
{
  __m128i xout1 = soft_aeskeygenassist_be(*xout2, rcon);
  xout1 = vec_perm(xout1,xout1,(__m128i){0x0,0x1,0x2,0x3, 0x0,0x1,0x2,0x3, 0x0,0x1,0x2,0x3, 0x0,0x1,0x2,0x3}); 
  *xout0 = sl_xor_be(*xout0);
  *xout0 = vec_xor(*xout0, xout1);
  xout1 = soft_aeskeygenassist_be(*xout0, 0x00);
  xout1 = vec_perm(xout1,xout1,(__m128i){0x4,0x5,0x6,0x7, 0x4,0x5,0x6,0x7, 0x4,0x5,0x6,0x7, 0x4,0x5,0x6,0x7});
  *xout2 = sl_xor_be(*xout2);
  *xout2 = vec_xor(*xout2, xout1);
}


template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3,
	__m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
	__m128i xout0, xout2;

	xout0 = vec_ld(0,memory);
	xout2 = vec_ld(16,memory);
	*k0 = xout0;
	*k1 = xout2;

		aes_genkey_sub<0x01>(&xout0, &xout2);
	*k2 = xout0;
	*k3 = xout2;

		aes_genkey_sub<0x02>(&xout0, &xout2);
	*k4 = xout0;
	*k5 = xout2;

		aes_genkey_sub<0x04>(&xout0, &xout2);
	*k6 = xout0;
	*k7 = xout2;

		aes_genkey_sub<0x08>(&xout0, &xout2);
	*k8 = xout0;
	*k9 = xout2;
}

template<bool SOFT_AES>
static inline void aes_genkey_be(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3,
	__m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
	__m128i xout0, xout2;

	xout0 = vec_ld(0,memory);
	xout2 = vec_ld(16,memory);
	xout0 = v_rev(xout0);
	xout2 = v_rev(xout2);
	
	*k0 = xout0;
	*k1 = xout2;

		aes_genkey_sub_be<0x01>(&xout0, &xout2);
	*k2 = xout0;
	*k3 = xout2;

		aes_genkey_sub_be<0x02>(&xout0, &xout2);
	*k4 = xout0;
	*k5 = xout2;

		aes_genkey_sub_be<0x04>(&xout0, &xout2);
	*k6 = xout0;
	*k7 = xout2;

		aes_genkey_sub_be<0x08>(&xout0, &xout2);
	*k8 = xout0;
	*k9 = xout2;
}
static inline void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = _mm_aesenc_si128(*x0, key);
	*x1 = _mm_aesenc_si128(*x1, key);
	*x2 = _mm_aesenc_si128(*x2, key);
	*x3 = _mm_aesenc_si128(*x3, key);
	*x4 = _mm_aesenc_si128(*x4, key);
	*x5 = _mm_aesenc_si128(*x5, key);
	*x6 = _mm_aesenc_si128(*x6, key);
	*x7 = _mm_aesenc_si128(*x7, key);
}

static inline void aes_round_be(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
 *x0 = _mm_aesenc_si128_be(*x0, key);
 *x1 = _mm_aesenc_si128_be(*x1, key);
 *x2 = _mm_aesenc_si128_be(*x2, key);
 *x3 = _mm_aesenc_si128_be(*x3, key);
 *x4 = _mm_aesenc_si128_be(*x4, key);
 *x5 = _mm_aesenc_si128_be(*x5, key);
 *x6 = _mm_aesenc_si128_be(*x6, key);
 *x7 = _mm_aesenc_si128_be(*x7, key);

}


inline void mix_and_propagate(__m128i& x0, __m128i& x1, __m128i& x2, __m128i& x3, __m128i& x4, __m128i& x5, __m128i& x6, __m128i& x7)
{
    __m128i tmp0 = x0;
    x0 = vec_xor(x0, x1);
    x1 = vec_xor(x1, x2);
    x2 = vec_xor(x2, x3);
    x3 = vec_xor(x3, x4);
    x4 = vec_xor(x4, x5);
    x5 = vec_xor(x5, x6);
    x6 = vec_xor(x6, x7);
    x7 = vec_xor(x7, tmp0);
}

template<size_t MEM, bool SOFT_AES, bool BE_MODE, xmrstak_algo ALGO>
void cn_explode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;
  aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);
  
  xin0 = vec_ld(64,input);
  xin1 = vec_ld(80,input);
  xin2 = vec_ld(96,input);
  xin3 = vec_ld(112,input);
  xin4 = vec_ld(128,input);
  xin5 = vec_ld(144,input);
  xin6 = vec_ld(160,input);
  xin7 = vec_ld(176,input);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    vec_st(xin0,i*16,output);
    vec_st(xin1,(i+1)*16,output);
    vec_st(xin2,(i+2)*16,output);
    vec_st(xin3,(i+3)*16,output);
    vec_st(xin4,(i+4)*16,output);
    vec_st(xin5,(i+5)*16,output);
    vec_st(xin6,(i+6)*16,output);
    vec_st(xin7,(i+7)*16,output);

	}
}

template<size_t MEM, bool SOFT_AES, bool BE_MODE, xmrstak_algo ALGO>
void cn_explode_scratchpad_heavy(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;
  aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);
  
  xin0 = vec_ld(64,input);
  xin1 = vec_ld(80,input);
  xin2 = vec_ld(96,input);
  xin3 = vec_ld(112,input);
  xin4 = vec_ld(128,input);
  xin5 = vec_ld(144,input);
  xin6 = vec_ld(160,input);
  xin7 = vec_ld(176,input);

  for(size_t i=0; i < 16; i++)
	{
    aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    mix_and_propagate(xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
  }

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    vec_st(xin0,i*16,output);
    vec_st(xin1,(i+1)*16,output);
    vec_st(xin2,(i+2)*16,output);
    vec_st(xin3,(i+3)*16,output);
    vec_st(xin4,(i+4)*16,output);
    vec_st(xin5,(i+5)*16,output);
    vec_st(xin6,(i+6)*16,output);
    vec_st(xin7,(i+7)*16,output);
	}
}

template<size_t MEM, bool SOFT_AES, bool BE_MODE, xmrstak_algo ALGO>
void cn_explode_scratchpad_be(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;
  aes_genkey_be<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);
  
  xin0 = vec_ld(64,input);
  xin1 = vec_ld(80,input);
  xin2 = vec_ld(96,input);
  xin3 = vec_ld(112,input);
  xin4 = vec_ld(128,input);
  xin5 = vec_ld(144,input);
  xin6 = vec_ld(160,input);
  xin7 = vec_ld(176,input);
  
  xin0 = v_rev(xin0);
  xin1 = v_rev(xin1);
  xin2 = v_rev(xin2);
  xin3 = v_rev(xin3);
  xin4 = v_rev(xin4);
  xin5 = v_rev(xin5);
  xin6 = v_rev(xin6);
  xin7 = v_rev(xin7);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		aes_round_be(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    vec_st(v_rev(xin0),i*16,output);
    vec_st(v_rev(xin1),(i+1)*16,output);
    vec_st(v_rev(xin2),(i+2)*16,output);
    vec_st(v_rev(xin3),(i+3)*16,output);
    vec_st(v_rev(xin4),(i+4)*16,output);
    vec_st(v_rev(xin5),(i+5)*16,output);
    vec_st(v_rev(xin6),(i+6)*16,output);
    vec_st(v_rev(xin7),(i+7)*16,output);

	}
}

template<size_t MEM, bool SOFT_AES, bool BE_MODE, xmrstak_algo ALGO>
void cn_explode_scratchpad_heavy_be(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;
  aes_genkey_be<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);
  
  xin0 = vec_ld(64,input);
  xin1 = vec_ld(80,input);
  xin2 = vec_ld(96,input);
  xin3 = vec_ld(112,input);
  xin4 = vec_ld(128,input);
  xin5 = vec_ld(144,input);
  xin6 = vec_ld(160,input);
  xin7 = vec_ld(176,input);
  
  xin0 = v_rev(xin0);
  xin1 = v_rev(xin1);
  xin2 = v_rev(xin2);
  xin3 = v_rev(xin3);
  xin4 = v_rev(xin4);
  xin5 = v_rev(xin5);
  xin6 = v_rev(xin6);
  xin7 = v_rev(xin7);

  for(size_t i=0; i < 16; i++)
	{
			aes_round_be(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round_be(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round_be(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round_be(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round_be(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round_be(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round_be(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round_be(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round_be(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round_be(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			mix_and_propagate(xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
	}

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		aes_round_be(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		aes_round_be(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    vec_st(v_rev(xin0),i*16,output);
    vec_st(v_rev(xin1),(i+1)*16,output);
    vec_st(v_rev(xin2),(i+2)*16,output);
    vec_st(v_rev(xin3),(i+3)*16,output);
    vec_st(v_rev(xin4),(i+4)*16,output);
    vec_st(v_rev(xin5),(i+5)*16,output);
    vec_st(v_rev(xin6),(i+6)*16,output);
    vec_st(v_rev(xin7),(i+7)*16,output);

	}
}


template<size_t MEM, bool SOFT_AES, bool BE_MODE, xmrstak_algo ALGO>
void cn_implode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);


  xout0 = vec_ld(64,output);
  xout1 = vec_ld(80,output);
  xout2 = vec_ld(96,output);
  xout3 = vec_ld(112,output);
  xout4 = vec_ld(128,output);
  xout5 = vec_ld(144,output);
  xout6 = vec_ld(160,output);
  xout7 = vec_ld(176,output);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{

    xout0 = vec_xor(vec_ld(i*16,input), xout0);
    xout1 = vec_xor(vec_ld((i+1)*16,input), xout1);
    xout2 = vec_xor(vec_ld((i+2)*16,input), xout2);
    xout3 = vec_xor(vec_ld((i+3)*16,input), xout3);
    xout4 = vec_xor(vec_ld((i+4)*16,input), xout4);
    xout5 = vec_xor(vec_ld((i+5)*16,input), xout5);
    xout6 = vec_xor(vec_ld((i+6)*16,input), xout6);
    xout7 = vec_xor(vec_ld((i+7)*16,input), xout7);
		aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
	}

  vec_st(xout0,64,output);
  vec_st(xout1,80,output);
  vec_st(xout2,96,output);
  vec_st(xout3,112,output);
  vec_st(xout4,128,output);
  vec_st(xout5,144,output);
  vec_st(xout6,160,output);
  vec_st(xout7,176,output);
}

template<size_t MEM, bool SOFT_AES, bool BE_MODE, xmrstak_algo ALGO>
void cn_implode_scratchpad_heavy(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);


  xout0 = vec_ld(64,output);
  xout1 = vec_ld(80,output);
  xout2 = vec_ld(96,output);
  xout3 = vec_ld(112,output);
  xout4 = vec_ld(128,output);
  xout5 = vec_ld(144,output);
  xout6 = vec_ld(160,output);
  xout7 = vec_ld(176,output);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{

    xout0 = vec_xor(vec_ld(i*16,input), xout0);
    xout1 = vec_xor(vec_ld((i+1)*16,input), xout1);
    xout2 = vec_xor(vec_ld((i+2)*16,input), xout2);
    xout3 = vec_xor(vec_ld((i+3)*16,input), xout3);
    xout4 = vec_xor(vec_ld((i+4)*16,input), xout4);
    xout5 = vec_xor(vec_ld((i+5)*16,input), xout5);
    xout6 = vec_xor(vec_ld((i+6)*16,input), xout6);
    xout7 = vec_xor(vec_ld((i+7)*16,input), xout7);
		aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
	}

		for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
		{

      xout0 = vec_xor(vec_ld(i*16,input), xout0);
      xout1 = vec_xor(vec_ld((i+1)*16,input), xout1);
      xout2 = vec_xor(vec_ld((i+2)*16,input), xout2);
      xout3 = vec_xor(vec_ld((i+3)*16,input), xout3);
      xout4 = vec_xor(vec_ld((i+4)*16,input), xout4);
      xout5 = vec_xor(vec_ld((i+5)*16,input), xout5);
      xout6 = vec_xor(vec_ld((i+6)*16,input), xout6);
      xout7 = vec_xor(vec_ld((i+7)*16,input), xout7);

      aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

      mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		}

		for(size_t i=0; i < 16; i++)
		{
      aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

			mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		}

  vec_st(xout0,64,output);
  vec_st(xout1,80,output);
  vec_st(xout2,96,output);
  vec_st(xout3,112,output);
  vec_st(xout4,128,output);
  vec_st(xout5,144,output);
  vec_st(xout6,160,output);
  vec_st(xout7,176,output);
}



template<size_t MEM, bool SOFT_AES, bool BE_MODE, xmrstak_algo ALGO>
void cn_implode_scratchpad_be(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey_be<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

  xout0 = vec_ld(64,output);
  xout1 = vec_ld(80,output);
  xout2 = vec_ld(96,output);
  xout3 = vec_ld(112,output);
  xout4 = vec_ld(128,output);
  xout5 = vec_ld(144,output);
  xout6 = vec_ld(160,output);
  xout7 = vec_ld(176,output);
  
  xout0 = v_rev(xout0);
  xout1 = v_rev(xout1);
  xout2 = v_rev(xout2);
  xout3 = v_rev(xout3);
  xout4 = v_rev(xout4);
  xout5 = v_rev(xout5);
  xout6 = v_rev(xout6);
  xout7 = v_rev(xout7);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{

    xout0 = vec_xor(v_rev(vec_ld(i*16,input)), xout0);
    xout1 = vec_xor(v_rev(vec_ld((i+1)*16,input)), xout1);
    xout2 = vec_xor(v_rev(vec_ld((i+2)*16,input)), xout2);
    xout3 = vec_xor(v_rev(vec_ld((i+3)*16,input)), xout3);
    xout4 = vec_xor(v_rev(vec_ld((i+4)*16,input)), xout4);
    xout5 = vec_xor(v_rev(vec_ld((i+5)*16,input)), xout5);
    xout6 = vec_xor(v_rev(vec_ld((i+6)*16,input)), xout6);
    xout7 = vec_xor(v_rev(vec_ld((i+7)*16,input)), xout7);
		aes_round_be(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
	}
  vec_st(v_rev(xout0),64,output);
  vec_st(v_rev(xout1),80,output);
  vec_st(v_rev(xout2),96,output);
  vec_st(v_rev(xout3),112,output);
  vec_st(v_rev(xout4),128,output);
  vec_st(v_rev(xout5),144,output);
  vec_st(v_rev(xout6),160,output);
  vec_st(v_rev(xout7),176,output);
}

template<size_t MEM, bool SOFT_AES, bool BE_MODE, xmrstak_algo ALGO>
void cn_implode_scratchpad_heavy_be(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey_be<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

  xout0 = vec_ld(64,output);
  xout1 = vec_ld(80,output);
  xout2 = vec_ld(96,output);
  xout3 = vec_ld(112,output);
  xout4 = vec_ld(128,output);
  xout5 = vec_ld(144,output);
  xout6 = vec_ld(160,output);
  xout7 = vec_ld(176,output);
  
  xout0 = v_rev(xout0);
  xout1 = v_rev(xout1);
  xout2 = v_rev(xout2);
  xout3 = v_rev(xout3);
  xout4 = v_rev(xout4);
  xout5 = v_rev(xout5);
  xout6 = v_rev(xout6);
  xout7 = v_rev(xout7);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{

    xout0 = vec_xor(v_rev(vec_ld(i*16,input)), xout0);
    xout1 = vec_xor(v_rev(vec_ld((i+1)*16,input)), xout1);
    xout2 = vec_xor(v_rev(vec_ld((i+2)*16,input)), xout2);
    xout3 = vec_xor(v_rev(vec_ld((i+3)*16,input)), xout3);
    xout4 = vec_xor(v_rev(vec_ld((i+4)*16,input)), xout4);
    xout5 = vec_xor(v_rev(vec_ld((i+5)*16,input)), xout5);
    xout6 = vec_xor(v_rev(vec_ld((i+6)*16,input)), xout6);
    xout7 = vec_xor(v_rev(vec_ld((i+7)*16,input)), xout7);
		aes_round_be(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		aes_round_be(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
	}

		for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
		{

      xout0 = vec_xor(v_rev(vec_ld(i*16,input)), xout0);
      xout1 = vec_xor(v_rev(vec_ld((i+1)*16,input)), xout1);
      xout2 = vec_xor(v_rev(vec_ld((i+2)*16,input)), xout2);
      xout3 = vec_xor(v_rev(vec_ld((i+3)*16,input)), xout3);
      xout4 = vec_xor(v_rev(vec_ld((i+4)*16,input)), xout4);
      xout5 = vec_xor(v_rev(vec_ld((i+5)*16,input)), xout5);
      xout6 = vec_xor(v_rev(vec_ld((i+6)*16,input)), xout6);
      xout7 = vec_xor(v_rev(vec_ld((i+7)*16,input)), xout7);

      aes_round_be(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round_be(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round_be(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round_be(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round_be(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round_be(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round_be(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round_be(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round_be(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round_be(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

      mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		}

		for(size_t i=0; i < 16; i++)
		{
      aes_round_be(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round_be(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round_be(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round_be(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round_be(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round_be(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round_be(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round_be(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round_be(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
      aes_round_be(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

			mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		}

  vec_st(v_rev(xout0),64,output);
  vec_st(v_rev(xout1),80,output);
  vec_st(v_rev(xout2),96,output);
  vec_st(v_rev(xout3),112,output);
  vec_st(v_rev(xout4),128,output);
  vec_st(v_rev(xout5),144,output);
  vec_st(v_rev(xout6),160,output);
  vec_st(v_rev(xout7),176,output);
}


inline void cryptonight_monero_tweak(uint64_t* mem_out, __m128i tmp)
{
  uint64_t* t = (uint64_t*)&tmp;
  mem_out[0] = t[0];
	uint8_t x = t[1] >> 24;
	const uint8_t index = (((x >> 3) & 6) | (x & 1)) << 1;
	mem_out[1] = t[1] ^ ((((uint16_t)0x7531 >> index) & 0x3) << 28);
}

template<xmrstak_algo ALGO, bool SOFT_AES, bool BE_MODE>
void cryptonight_hash(const void* input, size_t len, void* output, cryptonight_ctx* ctx0)
{
  constexpr size_t MASK = cn_select_mask<ALGO>();
	constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
	constexpr size_t MEM = cn_select_memory<ALGO>();

	if(ALGO == cryptonight_monero && len < 43)
	{
		memset(output, 0, 32);
		return;
	}

	keccak((const uint8_t *)input, len, ctx0->hash_state, 200);

	uint64_t monero_const;
	if(ALGO == cryptonight_monero)
	{
		monero_const  =  *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + 35);
		monero_const ^=  *(reinterpret_cast<const uint64_t*>(ctx0->hash_state) + 24);
	}

	// Optim - 99% time boundary
	if(ALGO == cryptonight_heavy){
    if(BE_MODE) cn_explode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
    else        cn_explode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
  }else{
    if(BE_MODE) cn_explode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
    else        cn_explode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
  }
	uint8_t* l0 = ctx0->long_state;
	uint64_t* h0 = (uint64_t*)ctx0->hash_state;

	uint64_t al0 = h0[0] ^ h0[4];
	uint64_t ah0 = h0[1] ^ h0[5];
	__m128i bx0 = (__m128ll){h0[2] ^ h0[6],h0[3] ^ h0[7]};

	uint64_t idx0 = al0;

	// Optim - 90% time boundary
	for(size_t i = 0; i < ITERATIONS; i++)
	{
		__m128i cx;
		cx = vec_vsx_ld(0,(__m128i *)&l0[idx0 & MASK]);
		cx = _mm_aesenc_si128(cx, (__m128ll){al0, ah0});

		if(ALGO == cryptonight_monero)
			cryptonight_monero_tweak((uint64_t*)&l0[idx0 & MASK], vec_xor(bx0, cx));
		else
			vec_vsx_st(vec_xor(bx0, cx),0,(__m128i *)&l0[idx0 & MASK]);
		
    idx0 = ((uint64_t*)&cx)[0];

		bx0 = cx;

		uint64_t hi, lo, cl, ch;
		cl = ((uint64_t*)&l0[idx0 & MASK])[0];
		ch = ((uint64_t*)&l0[idx0 & MASK])[1];

		lo = _umul128(idx0, cl, &hi);

		al0 += hi;
		((uint64_t*)&l0[idx0 & MASK])[0] = al0;
		al0 ^= cl;
		ah0 += lo;

		if(ALGO == cryptonight_monero)
			((uint64_t*)&l0[idx0 & MASK])[1] = ah0 ^ monero_const;
		else
			((uint64_t*)&l0[idx0 & MASK])[1] = ah0;
		ah0 ^= ch;

		idx0 = al0;

		if(ALGO == cryptonight_heavy)
		{
			int64_t n  = ((int64_t*)&l0[idx0 & MASK])[0];
			int32_t d  = ((int32_t*)&l0[idx0 & MASK])[2];
			int64_t q = n / (d | 0x5);

			((int64_t*)&l0[idx0 & MASK])[0] = n ^ q;
			idx0 = d ^ q;
		}
	}

	// Optim - 90% time boundary
	if(ALGO == cryptonight_heavy){
    if(BE_MODE) cn_implode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
  	else        cn_implode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
  }else{
    if(BE_MODE) cn_implode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
  	else        cn_implode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
  }

	// Optim - 99% time boundary

	keccakf((uint64_t*)ctx0->hash_state, 24);
	extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
}

// This lovely creation will do 2 cn hashes at a time. We have plenty of space on silicon
// to fit temporary vars for two contexts. Function will read len*2 from input and write 64 bytes to output
// We are still limited by L3 cache, so doubling will only work with CPUs where we have more than 2MB to core (Xeons)
template<xmrstak_algo ALGO, bool SOFT_AES, bool BE_MODE>
void cryptonight_double_hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
{
	constexpr size_t MASK = cn_select_mask<ALGO>();
	constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
	constexpr size_t MEM = cn_select_memory<ALGO>();

	if(ALGO == cryptonight_monero && len < 43)
	{
		memset(output, 0, 64);
		return;
	}

	keccak((const uint8_t *)input, len, ctx[0]->hash_state, 200);
	keccak((const uint8_t *)input+len, len, ctx[1]->hash_state, 200);

	uint64_t monero_const_0, monero_const_1;
	if(ALGO == cryptonight_monero)
	{
		monero_const_0  =  *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + 35);
		monero_const_0 ^=  *(reinterpret_cast<const uint64_t*>(ctx[0]->hash_state) + 24);
		monero_const_1  =  *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + len + 35);
		monero_const_1 ^=  *(reinterpret_cast<const uint64_t*>(ctx[1]->hash_state) + 24);
	}

	// Optim - 99% time boundary
	if(ALGO == cryptonight_heavy){
    if(BE_MODE){
      cn_explode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[0]->hash_state, (__m128i*)ctx[0]->long_state);
  	  cn_explode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[1]->hash_state, (__m128i*)ctx[1]->long_state);}
    else{
      cn_explode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[0]->hash_state, (__m128i*)ctx[0]->long_state);
  	  cn_explode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[1]->hash_state, (__m128i*)ctx[1]->long_state);}
  }else{
    if(BE_MODE){
      cn_explode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[0]->hash_state, (__m128i*)ctx[0]->long_state);
  	  cn_explode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[1]->hash_state, (__m128i*)ctx[1]->long_state);}
    else{
      cn_explode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[0]->hash_state, (__m128i*)ctx[0]->long_state);
  	  cn_explode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[1]->hash_state, (__m128i*)ctx[1]->long_state);}
  }

	uint8_t* l0 = ctx[0]->long_state;
	uint64_t* h0 = (uint64_t*)ctx[0]->hash_state;
	uint8_t* l1 = ctx[1]->long_state;
	uint64_t* h1 = (uint64_t*)ctx[1]->hash_state;

	uint64_t axl0 = h0[0] ^ h0[4];
	uint64_t axh0 = h0[1] ^ h0[5];
	__m128i bx0 = (__m128ll){h0[2] ^ h0[6],h0[3] ^ h0[7]};
	uint64_t axl1 = h1[0] ^ h1[4];
	uint64_t axh1 = h1[1] ^ h1[5];
	__m128i bx1 = (__m128ll){h1[2] ^ h1[6],h1[3] ^ h1[7]};

	uint64_t idx0 = h0[0] ^ h0[4];
	uint64_t idx1 = h1[0] ^ h1[4];

	// Optim - 90% time boundary
	for (size_t i = 0; i < ITERATIONS; i++)
	{
		__m128i cx;
		cx = vec_vsx_ld(0,(__m128i *)&l0[idx0 & MASK]);
		cx = _mm_aesenc_si128(cx, (__m128ll){axl0, axh0});

		if(ALGO == cryptonight_monero)
			cryptonight_monero_tweak((uint64_t*)&l0[idx0 & MASK], vec_xor(bx0, cx));
		else
			vec_vsx_st(vec_xor(bx0, cx),0,(__m128i *)&l0[idx0 & MASK]);

		idx0 = ((uint64_t*)&cx)[0];
		bx0 = cx;

		cx = vec_vsx_ld(0,(__m128i *)&l1[idx1 & MASK]);
		cx = _mm_aesenc_si128(cx, (__m128ll){axl1, axh1});

		if(ALGO == cryptonight_monero)
			cryptonight_monero_tweak((uint64_t*)&l1[idx1 & MASK], vec_xor(bx1, cx));
		else
		  vec_vsx_st(vec_xor(bx1, cx),0,(__m128i *)&l1[idx1 & MASK]);

		idx1 = ((uint64_t*)&cx)[0];
		bx1 = cx;


		uint64_t hi, lo, cl, ch;
		cl = ((uint64_t*)&l0[idx0 & MASK])[0];
		ch = ((uint64_t*)&l0[idx0 & MASK])[1];

		lo = _umul128(idx0, cl, &hi);

		axl0 += hi;
		axh0 += lo;
		((uint64_t*)&l0[idx0 & MASK])[0] = axl0;

		if(ALGO == cryptonight_monero)
			((uint64_t*)&l0[idx0 & MASK])[1] = axh0 ^ monero_const_0;
		else
			((uint64_t*)&l0[idx0 & MASK])[1] = axh0;

		axh0 ^= ch;
		axl0 ^= cl;
		idx0 = axl0;

		if(ALGO == cryptonight_heavy)
		{
			int64_t n  = ((int64_t*)&l0[idx0 & MASK])[0];
			int32_t d  = ((int32_t*)&l0[idx0 & MASK])[2];
			int64_t q = n / (d | 0x5);

			((int64_t*)&l0[idx0 & MASK])[0] = n ^ q;
			idx0 = d ^ q;
		}


		cl = ((uint64_t*)&l1[idx1 & MASK])[0];
		ch = ((uint64_t*)&l1[idx1 & MASK])[1];

		lo = _umul128(idx1, cl, &hi);

		axl1 += hi;
		axh1 += lo;
		((uint64_t*)&l1[idx1 & MASK])[0] = axl1;

		if(ALGO == cryptonight_monero)
			((uint64_t*)&l1[idx1 & MASK])[1] = axh1 ^ monero_const_1;
		else
			((uint64_t*)&l1[idx1 & MASK])[1] = axh1;

		axh1 ^= ch;
		axl1 ^= cl;
		idx1 = axl1;

		if(ALGO == cryptonight_heavy)
		{
			int64_t n  = ((int64_t*)&l1[idx1 & MASK])[0];
			int32_t d  = ((int32_t*)&l1[idx1 & MASK])[2];
			int64_t q = n / (d | 0x5);

			((int64_t*)&l1[idx1 & MASK])[0] = n ^ q;
			idx1 = d ^ q;
		}

	}

	// Optim - 90% time boundary
  if(ALGO == cryptonight_heavy){
    if(BE_MODE){
      cn_implode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[0]->long_state, (__m128i*)ctx[0]->hash_state);
	    cn_implode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[1]->long_state, (__m128i*)ctx[1]->hash_state);}
    else{
      cn_implode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[0]->long_state, (__m128i*)ctx[0]->hash_state);
    	cn_implode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[1]->long_state, (__m128i*)ctx[1]->hash_state);}
  }else{
    if(BE_MODE){
      cn_implode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[0]->long_state, (__m128i*)ctx[0]->hash_state);
	    cn_implode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[1]->long_state, (__m128i*)ctx[1]->hash_state);}
    else{
      cn_implode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[0]->long_state, (__m128i*)ctx[0]->hash_state);
    	cn_implode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[1]->long_state, (__m128i*)ctx[1]->hash_state);}
  }
	// Optim - 99% time boundary

	keccakf((uint64_t*)ctx[0]->hash_state, 24);
	extra_hashes[ctx[0]->hash_state[0] & 3](ctx[0]->hash_state, 200, (char*)output);
	keccakf((uint64_t*)ctx[1]->hash_state, 24);
	extra_hashes[ctx[1]->hash_state[0] & 3](ctx[1]->hash_state, 200, (char*)output + 32);
}

#define CN_STEP1(a, b, c, l, ptr, idx)				\
	ptr = (__m128i *)&l[idx & MASK];			\
	c = vec_vsx_ld(0,ptr); 

#define CN_STEP2(a, b, c, l, ptr, idx)				\
		c = _mm_aesenc_si128(c, a);			\
	b = vec_xor(b, c);				\
	if(ALGO == cryptonight_monero) \
		cryptonight_monero_tweak((uint64_t*)ptr, b); \
	else \
		vec_vsx_st(b,0,ptr);\

#define CN_STEP3(a, b, c, l, ptr, idx)				\
	idx = ((uint64_t*)&c)[0];				\
	ptr = (__m128i*)&l[idx & MASK];			\
	b = vec_vsx_ld(0,ptr);

#define CN_STEP4(a, b, c, l, mc, ptr, idx)				\
	lo = _umul128(idx, ((uint64_t*)&b)[0], &hi);		\
	a = (__m128ll)a + (__m128ll){hi, lo};		\
	if(ALGO == cryptonight_monero) \
		vec_vsx_st(vec_xor(a, mc),0,ptr); \
	else \
		vec_vsx_st(a,0,ptr);\
	a = vec_xor(a, b); \
	idx = ((uint64_t*)&a)[0];	\
	if(ALGO == cryptonight_heavy) \
	{ \
		int64_t n  = ((int64_t*)&l[idx & MASK])[0]; \
		int32_t d  = ((int32_t*)&l[idx & MASK])[2]; \
		int64_t q = n / (d | 0x5); \
		((int64_t*)&l[idx & MASK])[0] = n ^ q; \
		idx = d ^ q; \
	}

#define CONST_INIT(ctx, n) \
  __m128i mc##n = _mm_set_epi64x(*reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + n * len + 35) ^ \
    *(reinterpret_cast<const uint64_t*>((ctx)->hash_state) + 24), 0);
// This lovelier creation will do 3 cn hashes at a time.
template<xmrstak_algo ALGO, bool SOFT_AES, bool BE_MODE>
void cryptonight_triple_hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
{
	constexpr size_t MASK = cn_select_mask<ALGO>();
	constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
	constexpr size_t MEM = cn_select_memory<ALGO>();

	if(ALGO == cryptonight_monero && len < 43)
	{
		memset(output, 0, 32 * 3);
		return;
	}

	for (size_t i = 0; i < 3; i++)
	{
		keccak((const uint8_t *)input + len * i, len, ctx[i]->hash_state, 200);
		if(ALGO == cryptonight_heavy){
      if(BE_MODE) cn_explode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
      else        cn_explode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
    }else{
      if(BE_MODE) cn_explode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
      else        cn_explode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
    }
	}

	CONST_INIT(ctx[0], 0);
	CONST_INIT(ctx[1], 1);
	CONST_INIT(ctx[2], 2);

	uint8_t* l0 = ctx[0]->long_state;
	uint64_t* h0 = (uint64_t*)ctx[0]->hash_state;
	uint8_t* l1 = ctx[1]->long_state;
	uint64_t* h1 = (uint64_t*)ctx[1]->hash_state;
	uint8_t* l2 = ctx[2]->long_state;
	uint64_t* h2 = (uint64_t*)ctx[2]->hash_state;

	__m128i ax0 = (__m128ll){h0[0] ^ h0[4], h0[1] ^ h0[5]};
	__m128i bx0 = (__m128ll){h0[2] ^ h0[6], h0[3] ^ h0[7]};
	__m128i ax1 = (__m128ll){h1[0] ^ h1[4], h1[1] ^ h1[5]};
	__m128i bx1 = (__m128ll){h1[2] ^ h1[6], h1[3] ^ h1[7]};
	__m128i ax2 = (__m128ll){h2[0] ^ h2[4], h2[1] ^ h2[5]};
	__m128i bx2 = (__m128ll){h2[2] ^ h2[6], h2[3] ^ h2[7]};
	__m128i cx0 = (__m128ll){0, 0};
	__m128i cx1 = (__m128ll){0, 0};
	__m128i cx2 = (__m128ll){0, 0};

	uint64_t idx0, idx1, idx2;
	idx0 = ((uint64_t*)&ax0)[0];
	idx1 = ((uint64_t*)&ax1)[0];
	idx2 = ((uint64_t*)&ax2)[0];

	for (size_t i = 0; i < ITERATIONS/2; i++)
	{
		uint64_t hi, lo;
		__m128i *ptr0, *ptr1, *ptr2;

		// EVEN ROUND
		CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
		CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
		CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);

		CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
		CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
		CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);

		CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
		CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
		CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);

		CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
		CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
		CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);

		// ODD ROUND
		CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
		CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
		CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);

		CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
		CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
		CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);

		CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
		CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
		CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);

		CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
		CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
		CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
	}

	for (size_t i = 0; i < 3; i++)
	{
		if(ALGO == cryptonight_heavy){
      if(BE_MODE) cn_implode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
      else        cn_implode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
    }else{
      if(BE_MODE) cn_implode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
      else        cn_implode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
    }
    
		keccakf((uint64_t*)ctx[i]->hash_state, 24);
		extra_hashes[ctx[i]->hash_state[0] & 3](ctx[i]->hash_state, 200, (char*)output + 32 * i);
	}
}

// This even lovelier creation will do 4 cn hashes at a time.
template<xmrstak_algo ALGO, bool SOFT_AES, bool BE_MODE>
void cryptonight_quad_hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
{
	constexpr size_t MASK = cn_select_mask<ALGO>();
	constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
	constexpr size_t MEM = cn_select_memory<ALGO>();

	if(ALGO == cryptonight_monero && len < 43)
	{
		memset(output, 0, 32 * 4);
		return;
	}

	for (size_t i = 0; i < 4; i++)
	{
		keccak((const uint8_t *)input + len * i, len, ctx[i]->hash_state, 200);
		if(ALGO == cryptonight_heavy){
      if(BE_MODE) cn_explode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
      else        cn_explode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
    }else{
      if(BE_MODE) cn_explode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
      else        cn_explode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
    }
	}

	CONST_INIT(ctx[0], 0);
	CONST_INIT(ctx[1], 1);
	CONST_INIT(ctx[2], 2);
	CONST_INIT(ctx[3], 3);

	uint8_t* l0 = ctx[0]->long_state;
	uint64_t* h0 = (uint64_t*)ctx[0]->hash_state;
	uint8_t* l1 = ctx[1]->long_state;
	uint64_t* h1 = (uint64_t*)ctx[1]->hash_state;
	uint8_t* l2 = ctx[2]->long_state;
	uint64_t* h2 = (uint64_t*)ctx[2]->hash_state;
	uint8_t* l3 = ctx[3]->long_state;
	uint64_t* h3 = (uint64_t*)ctx[3]->hash_state;

	__m128i ax0 = (__m128ll){h0[0] ^ h0[4], h0[1] ^ h0[5]};
	__m128i bx0 = (__m128ll){h0[2] ^ h0[6], h0[3] ^ h0[7]};
	__m128i ax1 = (__m128ll){h1[0] ^ h1[4], h1[1] ^ h1[5]};
	__m128i bx1 = (__m128ll){h1[2] ^ h1[6], h1[3] ^ h1[7]};
	__m128i ax2 = (__m128ll){h2[0] ^ h2[4], h2[1] ^ h2[5]};
	__m128i bx2 = (__m128ll){h2[2] ^ h2[6], h2[3] ^ h2[7]};
	__m128i ax3 = (__m128ll){h3[0] ^ h3[4], h3[1] ^ h3[5]};
	__m128i bx3 = (__m128ll){h3[2] ^ h3[6], h3[3] ^ h3[7]};
	__m128i cx0 = (__m128ll){0, 0};
	__m128i cx1 = (__m128ll){0, 0};
	__m128i cx2 = (__m128ll){0, 0};
	__m128i cx3 = (__m128ll){0, 0};
	
	uint64_t idx0, idx1, idx2, idx3;
	idx0 = ((uint64_t*)&ax0)[0];
	idx1 = ((uint64_t*)&ax1)[0];
	idx2 = ((uint64_t*)&ax2)[0];
	idx3 = ((uint64_t*)&ax3)[0];
	
	for (size_t i = 0; i < ITERATIONS/2; i++)
	{
		uint64_t hi, lo;
		__m128i *ptr0, *ptr1, *ptr2, *ptr3;

		// EVEN ROUND
		CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
		CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
		CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);
		CN_STEP1(ax3, bx3, cx3, l3, ptr3, idx3);

		CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
		CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
		CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);
		CN_STEP2(ax3, bx3, cx3, l3, ptr3, idx3);

		CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
		CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
		CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);
		CN_STEP3(ax3, bx3, cx3, l3, ptr3, idx3);

		CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
		CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
		CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);
		CN_STEP4(ax3, bx3, cx3, l3, mc3, ptr3, idx3);

		// ODD ROUND
		CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
		CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
		CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);
		CN_STEP1(ax3, cx3, bx3, l3, ptr3, idx3);

		CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
		CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
		CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);
		CN_STEP2(ax3, cx3, bx3, l3, ptr3, idx3);

		CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
		CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
		CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);
		CN_STEP3(ax3, cx3, bx3, l3, ptr3, idx3);

		CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
		CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
		CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
		CN_STEP4(ax3, cx3, bx3, l3, mc3, ptr3, idx3);
	}

	for (size_t i = 0; i < 4; i++)
	{
		if(ALGO == cryptonight_heavy){
      if(BE_MODE) cn_implode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
      else        cn_implode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
    }else{
      if(BE_MODE) cn_implode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
      else        cn_implode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
    }
		keccakf((uint64_t*)ctx[i]->hash_state, 24);
		extra_hashes[ctx[i]->hash_state[0] & 3](ctx[i]->hash_state, 200, (char*)output + 32 * i);
	}
}

// This most lovely creation will do 5 cn hashes at a time.
template<xmrstak_algo ALGO, bool SOFT_AES, bool BE_MODE>
void cryptonight_penta_hash(const void* input, size_t len, void* output, cryptonight_ctx** ctx)
{
	constexpr size_t MASK = cn_select_mask<ALGO>();
	constexpr size_t ITERATIONS = cn_select_iter<ALGO>();
	constexpr size_t MEM = cn_select_memory<ALGO>();

	if(ALGO == cryptonight_monero && len < 43)
	{
		memset(output, 0, 32 * 5);
		return;
	}

	for (size_t i = 0; i < 5; i++)
	{
		keccak((const uint8_t *)input + len * i, len, ctx[i]->hash_state, 200);
		if(ALGO == cryptonight_heavy){
      if(BE_MODE) cn_explode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
      else        cn_explode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
    }else{
      if(BE_MODE) cn_explode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
      else        cn_explode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->hash_state, (__m128i*)ctx[i]->long_state);
    }
	}

	CONST_INIT(ctx[0], 0);
	CONST_INIT(ctx[1], 1);
	CONST_INIT(ctx[2], 2);
	CONST_INIT(ctx[3], 3);
	CONST_INIT(ctx[4], 4);

	uint8_t* l0 = ctx[0]->long_state;
	uint64_t* h0 = (uint64_t*)ctx[0]->hash_state;
	uint8_t* l1 = ctx[1]->long_state;
	uint64_t* h1 = (uint64_t*)ctx[1]->hash_state;
	uint8_t* l2 = ctx[2]->long_state;
	uint64_t* h2 = (uint64_t*)ctx[2]->hash_state;
	uint8_t* l3 = ctx[3]->long_state;
	uint64_t* h3 = (uint64_t*)ctx[3]->hash_state;
	uint8_t* l4 = ctx[4]->long_state;
	uint64_t* h4 = (uint64_t*)ctx[4]->hash_state;

	__m128i ax0 = (__m128ll){h0[0] ^ h0[4], h0[1] ^ h0[5]};
	__m128i bx0 = (__m128ll){h0[2] ^ h0[6], h0[3] ^ h0[7]};
	__m128i ax1 = (__m128ll){h1[0] ^ h1[4], h1[1] ^ h1[5]};
	__m128i bx1 = (__m128ll){h1[2] ^ h1[6], h1[3] ^ h1[7]};
	__m128i ax2 = (__m128ll){h2[0] ^ h2[4], h2[1] ^ h2[5]};
	__m128i bx2 = (__m128ll){h2[2] ^ h2[6], h2[3] ^ h2[7]};
	__m128i ax3 = (__m128ll){h3[0] ^ h3[4], h3[1] ^ h3[5]};
	__m128i bx3 = (__m128ll){h3[2] ^ h3[6], h3[3] ^ h3[7]};
	__m128i ax4 = (__m128ll){h4[0] ^ h4[4], h4[1] ^ h4[5]};
	__m128i bx4 = (__m128ll){h4[2] ^ h4[6], h4[3] ^ h4[7]};
	__m128i cx0 = (__m128ll){0, 0};
	__m128i cx1 = (__m128ll){0, 0};
	__m128i cx2 = (__m128ll){0, 0};
	__m128i cx3 = (__m128ll){0, 0};
	__m128i cx4 = (__m128ll){0, 0};

	uint64_t idx0, idx1, idx2, idx3, idx4;
	idx0 = ((uint64_t*)&ax0)[0];
	idx1 = ((uint64_t*)&ax1)[0];
	idx2 = ((uint64_t*)&ax2)[0];
	idx3 = ((uint64_t*)&ax3)[0];
	idx4 = ((uint64_t*)&ax4)[0];

	for (size_t i = 0; i < ITERATIONS/2; i++)
	{
		uint64_t hi, lo;
		__m128i *ptr0, *ptr1, *ptr2, *ptr3, *ptr4;

		// EVEN ROUND
		CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
		CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
		CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);
		CN_STEP1(ax3, bx3, cx3, l3, ptr3, idx3);
		CN_STEP1(ax4, bx4, cx4, l4, ptr4, idx4);

		CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
		CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
		CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);
		CN_STEP2(ax3, bx3, cx3, l3, ptr3, idx3);
		CN_STEP2(ax4, bx4, cx4, l4, ptr4, idx4);

		CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
		CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
		CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);
		CN_STEP3(ax3, bx3, cx3, l3, ptr3, idx3);
		CN_STEP3(ax4, bx4, cx4, l4, ptr4, idx4);

		CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
		CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
		CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);
		CN_STEP4(ax3, bx3, cx3, l3, mc3, ptr3, idx3);
		CN_STEP4(ax4, bx4, cx4, l4, mc4, ptr4, idx4);

		// ODD ROUND
		CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
		CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
		CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);
		CN_STEP1(ax3, cx3, bx3, l3, ptr3, idx3);
		CN_STEP1(ax4, cx4, bx4, l4, ptr4, idx4);

		CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
		CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
		CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);
		CN_STEP2(ax3, cx3, bx3, l3, ptr3, idx3);
		CN_STEP2(ax4, cx4, bx4, l4, ptr4, idx4);

		CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
		CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
		CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);
		CN_STEP3(ax3, cx3, bx3, l3, ptr3, idx3);
		CN_STEP3(ax4, cx4, bx4, l4, ptr4, idx4);

		CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
		CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
		CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
		CN_STEP4(ax3, cx3, bx3, l3, mc3, ptr3, idx3);
		CN_STEP4(ax4, cx4, bx4, l4, mc4, ptr4, idx4);
	}

	for (size_t i = 0; i < 5; i++)
	{
		if(ALGO == cryptonight_heavy){
      if(BE_MODE) cn_implode_scratchpad_heavy_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
      else        cn_implode_scratchpad_heavy<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
    }else{
      if(BE_MODE) cn_implode_scratchpad_be<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
      else        cn_implode_scratchpad<MEM, SOFT_AES, BE_MODE, ALGO>((__m128i*)ctx[i]->long_state, (__m128i*)ctx[i]->hash_state);
    }
		keccakf((uint64_t*)ctx[i]->hash_state, 24);
		extra_hashes[ctx[i]->hash_state[0] & 3](ctx[i]->hash_state, 200, (char*)output + 32 * i);
	}
}
