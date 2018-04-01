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
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting work.
  *
  */

/*,h
 * Parts of this file are originally copyright (c) 2014-2017, The Monero Project
 */
#include <altivec.h>
#undef vector
#undef pixel
#undef bool
typedef __vector unsigned char __m128i;
typedef __vector unsigned long long __m128ll;

static inline __m128i soft_aeskeygenassist(__m128i key, uint8_t rcon)
{
  key = __builtin_crypto_vsbox(vec_perm(key,key,(__m128i){0x4,0x5,0x6,0x7, 0x5,0x6,0x7,0x4, 0xc,0xd,0xe,0xf, 0xd,0xe,0xf,0xc}));
  return vec_xor(key,(__m128i){0,0,0,0, rcon,0,0,0, 0,0,0,0, rcon,0,0,0});
}

static inline __m128i soft_aeskeygenassist_be(__m128i key, uint8_t rcon)
{
  key = __builtin_crypto_vsbox(vec_perm(key,key,(__m128i){0x3,0x0,0x1,0x2, 0x0,0x1,0x2,0x3, 0xb,0x8,0x9,0xa, 0x8,0x9,0xa,0xb}));
  return vec_xor(key,(__m128i){0,0,0,rcon, 0,0,0,0, 0,0,0,rcon, 0,0,0,0});
}
