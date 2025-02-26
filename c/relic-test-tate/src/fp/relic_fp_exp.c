/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2010 RELIC Authors
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
 * Implementation of prime field exponentiation functions.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FP_EXP == BASIC || !defined(STRIP)

void fp_exp_basic(fp_t c, const fp_t a, const bn_t b) {
	size_t l;
	fp_t r;

	fp_null(r);

	if (bn_is_zero(b)) {
		fp_set_dig(c, 1);
		return;
	}

	RLC_TRY {
		fp_new(r);

		l = bn_bits(b);

		fp_copy(r, a);

		for (int i = l - 2; i >= 0; i--) {
			fp_sqr(r, r);
			if (bn_get_bit(b, i)) {
				fp_mul(r, r, a);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp_inv(c, r);
		} else {
			fp_copy(c, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(r);
	}
}

#endif

#if FP_EXP == SLIDE || !defined(STRIP)

void fp_exp_slide(fp_t c, const fp_t a, const bn_t b) {
	fp_t t[1 << (RLC_WIDTH - 1)], r;
	uint8_t win[RLC_FP_BITS + 1];
	size_t l;

	fp_null(r);

	if (bn_is_zero(b)) {
		fp_set_dig(c, 1);
		return;
	}


	/* Initialize table. */
	for (size_t i = 0; i < (1 << (RLC_WIDTH - 1)); i++) {
		fp_null(t[i]);
	}

	RLC_TRY {
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 1)); i ++) {
			fp_new(t[i]);
		}
		fp_new(r);

		fp_copy(t[0], a);
		fp_sqr(r, a);

		/* Create table. */
		for (size_t i = 1; i < 1 << (RLC_WIDTH - 1); i++) {
			fp_mul(t[i], t[i - 1], r);
		}

		fp_set_dig(r, 1);
		l = RLC_FP_BITS + 1;
		bn_rec_slw(win, &l, b, RLC_WIDTH);
		for (size_t i = 0; i < l; i++) {
			if (win[i] == 0) {
				fp_sqr(r, r);
			} else {
				for (size_t j = 0; j < util_bits_dig(win[i]); j++) {
					fp_sqr(r, r);
				}
				fp_mul(r, r, t[win[i] >> 1]);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp_inv(c, r);
		} else {
			fp_copy(c, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 1)); i++) {
			fp_free(t[i]);
		}
		fp_free(r);
	}
}

#endif

#if FP_EXP == MONTY || !defined(STRIP)

void fp_exp_monty(fp_t c, const fp_t a, const bn_t b) {
	fp_t t[2];

	fp_null(t[0]);
	fp_null(t[1]);

	if (bn_is_zero(b)) {
		fp_set_dig(c, 1);
		return;
	}

	RLC_TRY {
		fp_new(t[0]);
		fp_new(t[1]);

		fp_set_dig(t[0], 1);
		fp_copy(t[1], a);

		for (int i = bn_bits(b) - 1; i >= 0; i--) {
			int j = bn_get_bit(b, i);
			dv_swap_cond(t[0], t[1], RLC_FP_DIGS, j ^ 1);
			fp_mul(t[0], t[0], t[1]);
			fp_sqr(t[1], t[1]);
			dv_swap_cond(t[0], t[1], RLC_FP_DIGS, j ^ 1);
		}

		if (bn_sign(b) == RLC_NEG) {
			fp_inv(c, t[0]);
		} else {
			fp_copy(c, t[0]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t[1]);
		fp_free(t[0]);
	}
}


void fp_exp_z(fp_t a, const fp_t b){
    fp_t u0, u1, u2;
	bn_t n;
	bn_null(n);
	fp_null(u0);
	fp_null(u1);
	fp_null(u2);
	RLC_TRY{
		bn_new(n);
		fp_new(u0);
		fp_new(u1);
		fp_new(u2);
		switch (ep_curve_is_pairf()){
			case EP_B12:
				#if FP_PRIME==381
				fp_sqr(u0, b);
				fp_mul(u0, u0, b);	
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				for(int i=0;i<9;i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				for(int i=0;i<32;i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				for(int i=0;i<16;i++)fp_sqr(u0, u0);
				fp_copy(a, u0);			
				#elif FP_PRIME==446
				fp_sqr(u0, b);
				fp_mul(u0, u0, b);	
				for(int i=0;i<10;i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				for(int i=0;i<6;i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				for(int i=0;i<7;i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				for(int i=0;i<33;i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				for(int i=0;i<17;i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				fp_copy(a, u0);	
				#else
					fp_prime_get_par(n);
					if(bn_sign(n)==RLC_NEG)bn_neg(n,n);
					fp_exp(a, b, n);
				#endif
				break;
			case EP_B24:
				#if FP_PRIME==315
				fp_sqr(u0, b);
				fp_mul(u1, u0, b);//3
				fp_sqr(u2, u0);
				fp_sqr(u0, u2);
				fp_mul(u0, u0, u1);//11
				fp_mul(u2, u0, u2);

				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u2);
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);
				fp_mul(u0, u0, u1);
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);	
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u2);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u2);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u2);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u2);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u2);
				fp_copy(a, u0);
				#elif FP_PRIME==509
				fp_sqr(u0, b);
				fp_mul(u1, u0, b);
				fp_sqr(u2, u1);
				fp_sqr(u2, u2);
				fp_mul(u1, u1, u2);
				fp_mul(u0, u1, b);
				for(int i=0; i<23; i++)fp_sqr(u0, u0);
			    fp_mul(u0, u0, u1);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
			    fp_mul(u0, u0, u1);		
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
			    fp_mul(u0, u0, u1);	
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
			    fp_mul(u0, u0, u1);	
				fp_sqr(u0, u0);
			    fp_mul(u0, u0, b);		
				for(int i=0; i<11; i++)fp_sqr(u0, u0);
			    fp_mul(u0, u0, b);	
				fp_copy(a, u0);											
				#else
					fp_prime_get_par(n);
					if(bn_sign(n)==RLC_NEG)bn_neg(n,n);
					fp_exp(a, b, n);
				#endif
				break;	
			case EP_B48:
				#if FP_PRIME==575
				fp_sqr(u0, b);
				fp_mul(u1, u0, b);
				fp_sqr(u2, u0);
				fp_sqr(u0, u2);
				fp_mul(u1, u0, u1);//11
				fp_mul(u2, u1, u2);//15

				fp_sqr(u0, u2);
				for(int i=1; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u2);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u2);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u1);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u2);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u1);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_mul(u0, u0, u2);
				for(int i=0; i<4; i++)fp_sqr(u0, u0);
				fp_copy(a, u0);
				#else
					fp_prime_get_par(n);
					if(bn_sign(n)==RLC_NEG)bn_neg(n,n);
					fp_exp(a, b, n);
				#endif
				break;

			case EP_BW13:
				fp_sqr(u0, b);
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				fp_sqr(u0, u0);
				fp_mul(u0, u0, b);
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);
				fp_sqr(u0, u0);
				fp_copy(a, u0);
				break;
		}
	}RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		fp_free(u0);
		fp_free(u1);
		fp_free(u2);
	}

} 			


#endif
