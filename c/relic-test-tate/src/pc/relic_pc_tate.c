/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2013 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */
/**
 * @file
 *
 * Implementation of pairing computation utilities.
 *
 * @ingroup pc
 */
#include <stdio.h>
#include "relic_pc.h"
#include "relic_core.h"
#include"relic_fpx_low.h"
#include "relic_util.h"
#if defined(EP_ENDOM) && FP_PRIME == 310
/**
* points for G1 testing on a 310-bit pairing-friendly prime curve.
*/
/** @{ */
#define BW13_P310_X0	"18E88C0E7B077BE714C1A26358B6B874FC8E25AF18FB384A9D5229ACD2E20B5731224DA4DABEB"
#define BW13_P310_Y0    "C711E59625B33776B2E52EAD567D9D2E02136FA7AFBF81076A40FDCF2A2176CF3DDA68ADDDFCF"
/** @} */
#endif

#if defined(EP_ENDOM) && FP_PRIME == 315
/**
* points for G1 testing on a 315-bit pairing-friendly prime curve.
*/
/** @{ */
#define B24_P315_X0		"15CD452C509E688F0D693F4EFDBCC67EA4C36B4A0BD27F3A953F8249DA7BFC2094DCE84095F8760"
#define B24_P315_Y0		"B3D458D48B57D71EF1C3E272BFA46806CF4BA8C0E58E5AD122F629DA14CC538BAA6A8A71592ECF"
/** @} */
#endif

#if defined(EP_ENDOM) && FP_PRIME == 381
/**
* points for G1 testing on a 381-bit pairing-friendly prime curve.
*/
/** @{ */
#define B12_P381_X0		"D82B23C3EE86C6B55930A7755FEB499A697AAE08D97E677F61EBF6894E57EC7434DA198FE1FBF0EF1C7004640A74203"
#define B12_P381_Y0		"75868854578CF684F73F747280EF3F0A86CD94B3FB5954BC8B6FA4888BE7B2FB766E6DAF6F4F0AB9FE3E757B4BE8404"
/** @} */
#endif


#if defined(EP_ENDOM) && FP_PRIME == 446
/**
* points for G1 testing on a 446-bit pairing-friendly prime curve.
*/
/** @{ */
#define B12_P446_X0		"CAEAAD40BB81229158E00835E20E411F0BD8B1522DAF5E66E62CF4D7D85A4D7E3E5ECFC5045F0E1139869C5CB283696227797BF52FA2C3B"
#define B12_P446_Y0		"491CC9868EC9109E0D6FC21AA0081F2D4586BC7FD6C11F9CB19D8E26CB47C29292E8DC1D47E1C09749E995885D5AD22EECEC5CE4AEAE2BE"
/** @} */
#endif

#if defined(EP_ENDOM) && FP_PRIME == 509
/**
* points for G1 testing on a 509-bit pairing-friendly prime curve.
*/
/** @{ */
#define B24_P509_X0		"5F101D1D64A65ACE9C676C29031950976CFB980654DDA92EBE631764949A6B1E78BCDF34F86877AA04B7C3740DC26877E3C1397DF4F873BB90313C74B1E7F9B"
#define B24_P509_Y0		"10222E29D33B998B87E43D8645519B96BE69B1E8D6422E79209B7DDEA190D18E2E540A00416BC2A9E43EEDACDE535AA78418B1C37BE10AE5864C28ED45E18974"
/** @} */
#endif

#if defined(EP_ENDOM) && FP_PRIME == 575
/**
* points for G1 testing on a 575-bit pairing-friendly prime curve.
*/
/** @{ */
#define B48_P575_X0		"3A461A90C4243B832146CB2313A626F7F27588DFB0DE180DE045CD91BCC2B6B588A2845AAB40EC5171FA1E08CFF632B7B624C23565E6941595BF87D064E0819DFCC8023326D4D5A8"
#define B48_P575_Y0		"48E20CBA40C1F5905E5B70C0031EEEED6EF94D1AD9004D27B66859BCCCE29C8AFFDCC41893396F5A882F8D8C804E934FDC6809164CA6351E2D7DB8D0C700FBDA60105B59C5260E50"
/** @} */
#endif

#define ASSIGN_TEST(CURVE)							            \
	RLC_GET(str, CURVE##_X0, sizeof(CURVE##_X0));	            \
	fp_read_str(g->x, str, strlen(str), 16);  		            \
	RLC_GET(str, CURVE##_Y0, sizeof(CURVE##_Y0));	            \
	fp_read_str(g->y, str, strlen(str), 16);		            \	



void g1_tate_gen(g1_t g){
    char str[2 * RLC_FP_BYTES + 2];
	#if defined(EP_ENDOM) && FP_PRIME == 310
	ASSIGN_TEST(BW13_P310);
	#endif

	#if defined(EP_ENDOM) && FP_PRIME == 315
	ASSIGN_TEST(B24_P315);
	#endif
	
	#if defined(EP_ENDOM) && FP_PRIME == 381
	ASSIGN_TEST(B12_P381);
	#endif

	#if defined(EP_ENDOM) && FP_PRIME == 446
	ASSIGN_TEST(B12_P446);
	#endif
	
	#if defined(EP_ENDOM) && FP_PRIME == 509
	ASSIGN_TEST(B24_P509);
	#endif	
	
	#if defined(EP_ENDOM) && FP_PRIME == 575
	ASSIGN_TEST(B48_P575);
	#endif
	fp_set_dig(g->z, 1);
}

int g1_is_valid_tate(g1_t a, g1_t q) {
	size_t r = 0;

	if (g1_is_infty(a)) {
		return 0;
	}
	r = g1_on_curve(a) && test_tate(a, q);
	return r;
}

void tate_miller(fp_t N1, fp_t D1, fp_t N2, fp_t D2, g1_t q, g1_t p, g1_t p2){
	int i, j;
	bn_t n;
	ep_t t;
	ep_copy(t, q);
	fp_t f1, g1, f2, g2;
	int8_t s[RLC_FP_BITS + 1];
	size_t len;
	bn_null(n);
	ep_null(t);
	fp_null(f1);
	fp_null(g1);
	fp_null(f2);
	fp_null(g2);
	RLC_TRY {
	bn_new(n);
	ep_new(t);
	fp_new(f1);
	fp_new(g1);
	fp_new(f2);
	fp_new(g2);
		switch (ep_curve_is_pairf()){
			case EP_B12:
			case EP_B24:
			case EP_B48:
				fp_prime_get_par(n);
				bn_sub_dig(n, n, 1);
				if(bn_sign(n) == RLC_NEG)bn_neg(n, n);	
				bn_sub_dig(n, n, 1);	
				len = bn_bits(n) + 1;
				bn_rec_naf(s, &len, n, 2);
				i = len -2; 
				break;
			case EP_BW13:
				bn_t u;
				fp_prime_get_par(n);
				bn_sqr(u, n);
				bn_sub(n, u, n);	
				len = bn_bits(n) + 1;
				bn_rec_naf(s, &len, n, 2);
				i = len -2; 
				break;
		}
		j=0;
		if(s[0] <0 )j=1;
		while (i>=j){
			if(s[i] == 0 && i > j){
				tate_qpl(f1, g1, f2, g2, t, p, p2);
				fp_sqr(N1, N1);
				fp_sqr(N1, N1);

				fp_mul(N1, N1, f1);
				fp_sqr(D1, D1);
				fp_mul(D1, D1, g1);
				fp_sqr(D1, D1);	
			
				fp_sqr(N2, N2);
				fp_sqr(N2, N2);
				fp_mul(N2, N2, f2);
				fp_sqr(D2, D2);
				fp_mul(D2, D2, g2);
				fp_sqr(D2, D2);	
				i--;
				if(s[i] > 0){
					tate_add(f1, g1, f2, g2, t, q, p, p2);
					fp_mul(N1, N1, f1);
					fp_mul(D1, D1, g1);
					fp_mul(N2, N2, f2);
					fp_mul(D2, D2, g2);
				}
		        if(s[i] < 0){
					tate_sub(f1, g1, f2, g2, t, q, p, p2);
					fp_mul(N1, N1, f1);

					fp_mul(D1, D1, g1);
					fp_mul(N2, N2, f2);
					fp_mul(D2, D2, g2);
				}
				i--;									
			}
			else if(s[i] == 1){	
				tate_dba(f1, g1, f2, g2,  t, q, p, p2);
				fp_sqr(N1, N1);
				fp_mul(N1, N1, f1);		

				fp_sqr(D1, D1);
				fp_mul(D1, D1, g1);
				fp_sqr(N2, N2);
				fp_mul(N2, N2, f2);
				fp_sqr(D2, D2);
				fp_mul(D2, D2, g2);
				i--;		
			}
			else if(s[i]==-1){	
				tate_dbs(f1, g1, f2, g2,  t, q, p, p2);
				fp_sqr(N1, N1);
				fp_mul(N1, N1, f1);		

				fp_sqr(D1, D1);
				fp_mul(D1, D1, g1);
				fp_sqr(N2, N2);
				fp_mul(N2, N2, f2);
				fp_sqr(D2, D2);
				fp_mul(D2, D2, g2);
				i--;
			}
			else{
				tate_dbl(f1, g1, f2, g2, t, p, p2);
				fp_sqr(N1, N1);
				fp_mul(N1, N1, f1);			
				fp_sqr(D1, D1);
				fp_mul(D1, D1, g1);
				fp_sqr(N2, N2);
				fp_mul(N2, N2, f2);
				fp_sqr(D2, D2);
				fp_mul(D2, D2, g2);
				i--;
			}						
		
		}
		if(s[0] < 0){
			fp_sqr(f1, t->z);
			fp_mul(g1, f1, p->x );
			fp_sub(g1, g1, t->x);

			fp_copy(f2, f1);
			fp_mul(g2, f2, p2->x );
			fp_sub(g2, g2, t->x);

			fp_sqr(N1, N1);
			fp_mul(N1, N1, f1);			
			fp_sqr(D1, D1);
			fp_mul(D1, D1, g1);
			fp_sqr(N2, N2);
			fp_mul(N2, N2, f2);
			fp_sqr(D2, D2);
			fp_mul(D2, D2, g2);	
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
	bn_free(n);
	ep_free(t);
	fp_free(f1);
	fp_free(g1);
	fp_free(f2);
	fp_free(g2);
	}
}


int test_tate(g1_t p, g1_t q){
	fp_t N1, D1, N2, D2;
	ep_t p2;
	int r = 0;
	ep_null(p2);
	fp_null(N1);
	fp_null(D1);
	fp_null(N2);
	fp_null(D2);
	RLC_TRY {
		ep_new(p2);
		fp_new(N1);
		fp_new(D1);
		fp_new(N2);
		fp_new(D2);
		ep_psi(p2, p);
		fp_sub(N1, p->x, q->x);
		fp_sub(N2, p2->x, q->x);
		fp_set_dig(D1, 1);
		fp_set_dig(D2, 1);
		tate_miller(N1, D1, N2, D2, q, p, p2);	
		if(fp_is_zero(N1)||fp_is_zero(D1)||fp_is_zero(N2)||fp_is_zero(D2)){
			return r;
		}
		else{
			fp_mul(N1, N1, D2);
			fp_mul(N2, N2, D1);
			fp_mul(D1, D1, D2);
			fp_inv(D1, D1);
			fp_mul(N1, N1, D1);
			fp_mul(N2, N2, D1);	
			#if FP_PRIME == 315	
				tate_exp2(N1, N1);
				tate_exp2(N2, N2);
				r = (fp_cmp_dig(N1,1)== RLC_EQ) && (fp_cmp_dig(N2,1)== RLC_EQ);
			#else
				tate_exp1(N1, D1, N1);
				tate_exp2(N2, N2);
				r = (fp_cmp(N1,D1)== RLC_EQ) && (fp_cmp_dig(N2,1)== RLC_EQ);
			#endif
			return r;
			}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(p2);
		fp_free(N1);
		fp_free(D1);
		fp_free(N2);
		fp_free(D2);
	}
}


void miller_tab(fp_t *tab, g1_t q){
	int i,j,k;
	int8_t s[RLC_FP_BITS + 1];
	size_t len;
	bn_t n;
	fp_t u0, u1;
	ep_t t0,t1, _q;
	fp_prime_get_par(n);
	switch (ep_curve_is_pairf()){
				case EP_B12:
				case EP_B24:
				case EP_B48:
					fp_prime_get_par(n);
					bn_sub_dig(n, n, 1);
					if(bn_sign(n) == RLC_NEG)bn_neg(n, n);	
					bn_sub_dig(n, n, 1);	
					len = bn_bits(n) + 1;
					bn_rec_naf(s, &len, n, 2);
					i = len -2; 
					break;
				case EP_BW13:
					bn_t u;
					fp_prime_get_par(n);
					bn_sqr(u, n);
					bn_sub(n, u, n);	
					len = bn_bits(n) + 1;
					bn_rec_naf(s, &len, n, 2);
					i = len -2; 
					break;
			}
	j=0;k=0;
	ep_copy(t0, q);
	ep_neg(_q, q);
	if(s[0] <0 )j=1;
	while (i>=j){
		if(s[i] == 0 && i > j){
			fp_sqr(u0, t0->x);
			fp_dbl(u1, u0);
			fp_add(u0, u0, u1);
			fp_dbl(u1, t0->y);
			fp_inv(u1, u1);
			fp_neg(u1, u1);
			fp_mul(tab[k], u0, u1);
			ep_dbl_basic(t0, t0);
			fp_sqr(u0, t0->x);
			fp_dbl(u1, u0);
			fp_add(u0, u0, u1);
			fp_dbl(u1, t0->y);
			fp_inv(u1, u1);
			fp_copy(tab[k+1], t0->x);
			fp_copy(tab[k+2], t0->y);
			fp_mul(tab[k+3], u0, u1);
			ep_dbl_basic(t0, t0);
			k=k+4;
			i--;
			//[l_{-T}, 2T->x, 2T->y, l_{2T}]
			if(s[i] > 0){
				fp_sub(u0, t0->y, q->y);
				fp_sub(u1, t0->x, q->x);
				fp_inv(u1, u1);
				fp_mul(tab[k], u0, u1);
				fp_copy(tab[k+1], t0->x);
				k=k+2;
				ep_add_basic(t0, t0, q);

				//[l_{T+q}, T->x]	
			}
		    if(s[i] < 0){
				fp_add(u0, t0->y, q->y);
				fp_sub(u1, q->x, t0->x);
				fp_inv(u1, u1);
				fp_mul(tab[k], u0, u1);
				ep_add_basic(t0, t0, _q);	
				fp_copy(tab[k+1], t0->x);
				k=k+2;
				//[l_{T-q}, (T-q)->x]	
			}
			i--;									
		}
		else if(s[i] == 1){	
			fp_copy(tab[k], t0->x);
			fp_copy(tab[k+1], t0->y);
			fp_sub(u0, t0->y, q->y);
			fp_sub(u1, t0->x, q->x);
			fp_inv(tab[k+2], u1);
			fp_mul(tab[k+2],tab[k+2],u0);//lambda_T,P

			ep_add_basic(t1, t0, q);	
			fp_sub(u0, t1->y, t0->y);
			fp_sub(u1, t1->x, t0->x);
			fp_inv(tab[k+3], u1);
			fp_mul(tab[k+3],tab[k+3],u0);//lambda_T+P,T	

			fp_mul(u0, tab[k+2], tab[k+3]);
			fp_add(tab[k+3], tab[k+2], tab[k+3]);
			fp_add(tab[k+2], u0, t0->x);
			fp_add(tab[k+2], tab[k+2], t1->x);
			ep_add_basic(t0, t1, t0);
			k=k+4;
			i--;	
		}
		else if(s[i]==-1){	
			fp_copy(tab[k], t0->x);
			fp_copy(tab[k+1], t0->y);
			fp_add(u0, t0->y, q->y);
			fp_sub(u1, t0->x, q->x);
			fp_inv(tab[k+2], u1);
			fp_mul(tab[k+2],tab[k+2],u0);//lambda_T,-P

			ep_sub(t1, t0, q);	
			ep_norm(t1, t1);
			fp_sub(u0, t1->y, t0->y);
			fp_sub(u1, t1->x, t0->x);
			fp_inv(tab[k+3], u1);
			fp_mul(tab[k+3],tab[k+3],u0);//lambda_T-P,T	

			fp_mul(u0, tab[k+2], tab[k+3]);
			fp_add(tab[k+3], tab[k+2], tab[k+3]);
			fp_add(tab[k+2], u0, t0->x);
			fp_add(tab[k+2], tab[k+2], t1->x);
			ep_add_basic(t0, t1, t0);
			k=k+4;
			i--;			

		}
		else{
			fp_sqr(u0, t0->x);
			fp_dbl(u1, u0);
			fp_add(u0, u0, u1);
			fp_dbl(u1, t0->y);
			fp_inv(u1, u1);
			fp_neg(u1, u1);
			fp_mul(tab[k], u0, u1);
			ep_dbl_basic(t0, t0);
			fp_copy(tab[k+1], t0->x);
			fp_copy(tab[k+2], t0->y);	
			i--;
			k=k+3;
			//[l_{-T，-T}， 2T->x, 2T->y]
		}						
		
	}
	if(s[0] < 0)fp_copy(tab[k], t0->x);	
}

void tate_miller_pre(fp_t *tab, fp_t N1, fp_t D1, fp_t N2, fp_t D2, g1_t q, g1_t p, g1_t p2){
	int i, j, k;
	bn_t n;
	ep_t t;
	ep_copy(t, q);
	fp_t f1, g1, f2, g2, u0, u1, u2, u3;
	dv_t v0, v1, v2;
	int8_t s[RLC_FP_BITS + 1];
	size_t len;
	bn_null(n);
	ep_null(t);
	fp_null(f1);
	fp_null(g1);
	fp_null(f2);
	fp_null(g2);
	RLC_TRY {
	bn_new(n);
	ep_new(t);
	fp_new(f1);
	fp_new(g1);
	fp_new(f2);
	fp_new(g2);
		switch (ep_curve_is_pairf()){
			case EP_B12:
			case EP_B24:
			case EP_B48:
				fp_prime_get_par(n);
				bn_sub_dig(n, n, 1);
				if(bn_sign(n) == RLC_NEG)bn_neg(n, n);	
				bn_sub_dig(n, n, 1);	
				len = bn_bits(n) + 1;
				bn_rec_naf(s, &len, n, 2);
				i = len-2; 
				break;
			case EP_BW13:
				bn_t u;
				fp_prime_get_par(n);
				bn_sqr(u, n);
				bn_sub(n, u, n);	
				len = bn_bits(n) + 1;
				bn_rec_naf(s, &len, n, 2);
				i = len -2; 
				break;
		}
		j=0;k=0;
		if(s[0] < 0)j=1;
		fp_sub(u1, p->y, q->y);//d3
		fp_sub(u2, p->x, q->x);//d1
		fp_sub(u3, p2->x, q->x);//d2
		while (i>=j){
			if(s[i] == 0 && i > j){
				fp_sub(u0, p->y, tab[k+2]);
				fp_sub(f1, p->x, tab[k+1]);
				fp_sub(f2, p2->x, tab[k+1]);				
				fp_mul(g1, f1, tab[k]);
				fp_sub(g1, u0, g1);
				fp_mul(g2, f2, tab[k]);
				fp_sub(g2, u0, g2);	
				
				fp_mul(f1, f1, tab[k+3]);
				fp_sub(f1, u0, f1);
				fp_mul(f2, f2, tab[k+3]);
				fp_sub(f2, u0, f2);



				fp_sqr(N1, N1);
				fp_sqr(N1, N1);

				fp_mul(N1, N1, f1);
				fp_sqr(D1, D1);
				fp_mul(D1, D1, g1);
				fp_sqr(D1, D1);	
			
				fp_sqr(N2, N2);
				fp_sqr(N2, N2);
				fp_mul(N2, N2, f2);
				fp_sqr(D2, D2);
				fp_mul(D2, D2, g2);
				fp_sqr(D2, D2);	
				k=k+4;
				i--;
				if(s[i] > 0){
					
					fp_mul(f1, tab[k], u2);
					fp_sub(f1, u1, f1);
					fp_mul(f2, tab[k], u3);
					fp_sub(f2, u1, f2);
					fp_sub(g1, p->x, tab[k+1]);
					fp_sub(g2, p2->x, tab[k+1]);

					fp_mul(N1, N1, f1);
					fp_mul(D1, D1, g1);
					fp_mul(N2, N2, f2);	
					fp_mul(D2, D2, g2);
					k=k+2;

				}
		        if(s[i] < 0){
					fp_sub(f1, p->x, tab[k+1]);
					fp_sub(f2, p2->x, tab[k+1]);
					fp_mul(g1, tab[k], u2);
					fp_sub(g1, u1, g1);
					fp_mul(g2, tab[k], u3);
					fp_sub(g2, u1, g2);	

					fp_mul(N1, N1, f1);
					fp_mul(D1, D1, g1);
					fp_mul(N2, N2, f2);
					fp_mul(D2, D2, g2);

					k=k+2;
				}
				i--;									
			}
			else if(s[i] == 1){	
				fp_sub(u0, p->x, tab[k]);
				fp_sub(g1, p2->x, tab[k]);
				fp_add(g2, p->x, tab[k+2]);
				fp_add(f1, p2->x, tab[k+2]);
				fp_muln_low(v0, u0, g2);
				fp_muln_low(v1, g1, f1);
				fp_sub(g2, p->y, tab[k+1]);
				fp_muln_low(v2, g2, tab[k+3]);
				fp_subc_low(v0, v0, v2);
				fp_subc_low(v1, v1, v2);
				fp_rdc(f1, v0);
				fp_rdc(f2, v1);

				fp_sqr(N1, N1);
				fp_mul(N1, N1, f1);		
				fp_mul(D1, D1, u0);
				fp_sqr(D1, D1);

				fp_sqr(N2, N2);
				fp_mul(N2, N2, f2);
				fp_mul(D2, D2, g1);
				fp_sqr(D2, D2);
				k=k+4;
				i--;							
			}
			else if(s[i]==-1){	
				fp_sub(u0, p->x, tab[k]);
				fp_sub(g1, p2->x, tab[k]);
				fp_add(g2, p->x, tab[k+2]);
				fp_add(f1, p2->x, tab[k+2]);
				fp_muln_low(v0, u0, g2);
				fp_muln_low(v1, g1, f1);
				fp_sub(g2, p->y, tab[k+1]);
				fp_muln_low(v2, g2, tab[k+3]);
				fp_subc_low(v0, v0, v2);
				fp_subc_low(v1, v1, v2);
				fp_rdc(f1, v0);
				fp_rdc(f2, v1);

				fp_sqr(N1, N1);
				fp_mul(N1, N1, f1);		
				fp_mul(D1, D1, u0);
				fp_sqr(D1, D1);
				fp_mul(D1, D1, u2);

				fp_sqr(N2, N2);
				fp_mul(N2, N2, f2);
				fp_mul(D2, D2, g1);
				fp_sqr(D2, D2);
				fp_mul(D2, D2, u3);
				k=k+4;
				i--;				
			}
			else{
				fp_sub(f1, p->x, tab[k+1]);
				fp_sub(f2, p2->x, tab[k+1]);
				
				fp_sub(u0, p->y, tab[k+2]);
				fp_mul(g1, tab[k], f1);
				fp_sub(g1, u0, g1);
				fp_mul(g2, tab[k], f2);
				fp_sub(g2, u0, g2);				
				fp_sqr(N1, N1);
				fp_mul(N1, N1, f1);			
				fp_sqr(D1, D1);
				fp_mul(D1, D1, g1);
				fp_sqr(N2, N2);
				fp_mul(N2, N2, f2);
				fp_sqr(D2, D2);
				fp_mul(D2, D2, g2);
				k=k+3;
				i--;
			}						
		
		}
		if(s[0] < 0){
			
			fp_sub(g1, p->x, tab[k]);
			fp_sub(g2, p2->x, tab[k]);
			fp_sqr(N1, N1);
			fp_sqr(D1, D1);
			fp_mul(D1, D1, g1);
			fp_sqr(N2, N2);
			fp_sqr(D2, D2);
			fp_mul(D2, D2, g2);	
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
	bn_free(n);
	ep_free(t);
	fp_free(f1);
	fp_free(g1);
	fp_free(f2);
	fp_free(g2);
	}
}

int test_tate_pre(g1_t p, g1_t q, fp_t *tab){
	fp_t N1, D1, N2, D2;
	ep_t p2;
	int r = 0;
	ep_null(p2);
	fp_null(N1);
	fp_null(D1);
	fp_null(N2);
	fp_null(D2);
	RLC_TRY {
		ep_new(p2);
		fp_new(N1);
		fp_new(D1);
		fp_new(N2);
		fp_new(D2);
		ep_psi(p2, p);
		fp_sub(N1, p->x, q->x);
		fp_sub(N2, p2->x, q->x);
		fp_set_dig(D1, 1);
		fp_set_dig(D2, 1);
		tate_miller_pre(tab, N1, D1,N2, D2, q, p, p2);
		if(fp_is_zero(N1)||fp_is_zero(D1)||fp_is_zero(N2)||fp_is_zero(D2)){
			return r;
		}
		else{
			fp_mul(N1, N1, D2);
			fp_mul(N2, N2, D1);
			fp_mul(D1, D1, D2);
			fp_inv(D1, D1);
			fp_mul(N1, N1, D1);
			fp_mul(N2, N2, D1);		
			tate_exp1(N1, D1, N1);
			tate_exp2(N2, N2);
			r = (fp_cmp(N1,D1)== RLC_EQ) && (fp_cmp_dig(N2,1)== RLC_EQ);
			return r;
			}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(p2);
		fp_free(N1);
		fp_free(D1);
		fp_free(N2);
		fp_free(D2);
	}
}

int g1_is_valid_tate_pre(g1_t a, g1_t q, fp_t* tab) {
	size_t r = 0;

	if (g1_is_infty(a)) {
		return 0;
	}
	r = g1_on_curve(a) && test_tate_pre(a, q, tab);
	return r;
}