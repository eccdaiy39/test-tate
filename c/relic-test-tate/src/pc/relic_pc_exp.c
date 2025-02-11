/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2020 RELIC Authors
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
 * Implementation of exponentiation in pairing groups.
 *
 * @ingroup pc
 */

#include "relic_pc.h"
#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void g1_mul(g1_t c, const g1_t a, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	if (bn_bits(b) <= RLC_DIG) {
		g1_mul_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			g1_neg(c, c);
		}
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G1_LOWER, mul)(c, a, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g1_mul_gen(g1_t c, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G1_LOWER, mul_gen)(c, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g2_mul(g2_t c, const g2_t a, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	if (bn_bits(b) <= RLC_DIG) {
		g2_mul_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			g2_neg(c, c);
		}
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G2_LOWER, mul)(c, a, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g2_mul_gen(g2_t c, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G2_LOWER, mul_gen)(c, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void gt_exp(gt_t c, const gt_t a, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	if (bn_bits(b) <= RLC_DIG) {
		gt_exp_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			gt_inv(c, c);
		}
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_GT_LOWER, exp_cyc)(c, a, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void gt_exp_dig(gt_t c, const gt_t a, dig_t b) {
	gt_t t;

	if (b == 0) {
		gt_set_unity(c);
		return;
	}

	gt_null(t);

	RLC_TRY {
		gt_new(t);

		gt_copy(t, a);
		for (int i = util_bits_dig(b) - 2; i >= 0; i--) {
			gt_sqr(t, t);
			if (b & ((dig_t)1 << i)) {
				gt_mul(t, t, a);
			}
		}

		gt_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		gt_free(t);
	}
}

void gt_exp_sim(gt_t e, const gt_t a, const bn_t b, const gt_t c, const bn_t d) {
	bn_t n, _b, _d;

	bn_null(n);
	bn_null(_b);
	bn_null(_d);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);
		bn_new(_d);

		gt_get_ord(n);
		bn_mod(_b, b, n);
		bn_mod(_d, d, n);

		RLC_CAT(RLC_GT_LOWER, exp_cyc_sim)(e, a, _b, c, _d);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
		bn_free(_d);
	}
}

void gt_exp_gen(gt_t c, const bn_t b) {
	bn_t n, _b;
	gt_t g;

	bn_null(n);
	bn_null(_b);
	gt_null(g);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);
		gt_new(g);

		pc_get_ord(n);
		bn_mod(_b, b, n);
		gt_get_gen(g);
		gt_exp(c, g, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
		gt_free(g);
	}
}


void tate_exp1(fp_t a, fp_t c, fp_t b){
	bn_t n;
	fp_t u0, u1, u2, u3;
	bn_null(n);
	fp_null(u0);
	fp_null(u1);
	fp_null(u2);
	fp_null(u3);
	RLC_TRY {
		bn_new(n);
		fp_new(u0);
		fp_new(u1);
		fp_new(u2);
		fp_new(u3);				
		fp_prime_get_par(n);
		switch (ep_curve_is_pairf()){
			case EP_BW13:
				if (bn_sign(n) == RLC_NEG){
					bn_neg(n, n);
					fp_exp_z(u1, b);
					fp_exp_z(u1, u1);
					fp_exp_z(u0, u1);
					fp_exp_z(u2, u0);
					fp_exp_z(u2, u2);
					fp_mul(u1, u1, u2);
					fp_exp_z(u2, u2);
					fp_mul(u0, u0, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_mul(u1, u1, u2);
					fp_exp_z(u2, u2);
					fp_mul(u0, u0, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_mul(u1, u1, u2);
					fp_exp_z(u2, u2);
					fp_mul(u0, u0, u2);

					fp_sqr(u3, u0);
					fp_mul(u0, u0, u3);
					fp_sqr(u3, b);
					fp_mul(u0, u0, u3);

					fp_sqr(u3, u1);
					fp_mul(u1, u1, u3);
					fp_exp_z(u2, u2);
					fp_mul(u1, u1, u2);
					for(int i= 0;i < 13; i++)fp_exp_z(u2, u2);
					fp_mul(u1, u1, u2);
	
					fp_copy(a, u0);
					fp_copy(c, u1);
				}
				else {
					fp_exp_z(u1, b);
					fp_exp_z(u1, u1);
					fp_exp_z(u2, u1);
					fp_mul(u1, u1, u2);

					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u3, u2);
					fp_mul(u2, u2, u3);
					fp_exp_z(u3, u3);
					fp_exp_z(u3, u3);
					fp_mul(u1, u1, u3);
					fp_exp_z(u3, u3);
					fp_mul(u1, u1, u3);
					fp_exp_z(u3, u3);
					fp_exp_z(u3, u3);
					fp_mul(u2, u2, u3);
					fp_exp_z(u3, u3);
					fp_mul(u2, u2, u3);
					fp_sqr(u0, u2);
					fp_mul(u0, u0, u2);
					fp_sqr(u2, b);
					fp_mul(u0, u0, u2);
					fp_exp_z(u3, u3);
					fp_mul(u0, u0, u3);
					for(int i= 0;i < 13; i++)fp_exp_z(u3, u3);
					fp_sqr(u2, u1);
					fp_mul(u1, u1, u2);
					fp_mul(u1, u1, u3);
					fp_copy(a, u0);
					fp_copy(c, u1);
				}
				break;

			case EP_B12:
				if (bn_sign(n) == RLC_NEG){
					fp_sqr(u0, b);
					fp_exp_z(u1, b);
					fp_exp_z(u2, u1);
					fp_exp_z(u3, u2);
					fp_mul(u0, u0, u2);
					fp_mul(u0, u0, u3);
					fp_exp_z(u3, u3);
					fp_mul(u1, u1, u3);
					fp_exp_z(u3, u3);
					fp_mul(u1, u1, u3);
					fp_copy(a, u0);
					fp_copy(c, u1);
				}
				else {
					fp_sqr(u0, b);
					fp_exp_z(u1, b);
					fp_mul(u0, u0, u1);//f^(z+2)
					fp_exp_z(u1, u1);
					fp_mul(u0, u0, u1);//f^(z^2+z+2)
					fp_exp_z(u2, u1);
					fp_exp_z(u3, u2);
					fp_mul(u1, u2, u3);
					fp_exp_z(u2, u3);
					fp_mul(u0, u0, u2);
					fp_copy(a, u0);
					fp_copy(c, u1);
				}
				break;

			case EP_B24:
				// #if FP_PRIME==509
				// 	bn_t p;
				// 	p->used = RLC_FP_DIGS;
				// 	dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
				// 	bn_sub_dig(p, p, 1);
				// 	fp_prime_get_par(n);
				// 	bn_neg(n, n);
				// 	bn_add_dig(n, n, 1);
				// 	bn_div_dig(n, n, 3);
				// 	bn_div(n, p, n);
				// 	fp_exp(c, b, n);
				// 	fp_copy(a, c);
				// #else
					if (bn_sign(n) == RLC_NEG){
						bn_neg(n, n);
						fp_sqr(u0, b);
						fp_exp_z(u1, b);
						fp_exp_z(u2, u1);
						fp_exp_z(u2, u2);
						fp_exp_z(u2, u2);
						fp_mul(u0, u0, u2);
						fp_exp_z(u2, u2);
						fp_mul(u0, u0, u2);
						fp_exp_z(u2, u2);
						fp_exp_z(u2, u2);
						fp_exp_z(u2, u2);
						fp_exp_z(u3, u2);
						fp_mul(u1, u1, u2);
						fp_mul(u1, u1, u3);
						fp_copy(a, u0);
						fp_copy(c, u1);
					}
					else {
						fp_sqr(u0, b);
						fp_exp_z(u1, b);
						fp_mul(u0, u0, u1);
						fp_exp_z(u1, u1);
						fp_exp_z(u1, u1);
						fp_exp_z(u1, u1);
						fp_mul(u0, u0, u1);
						fp_exp_z(u2, u1);
						fp_exp_z(u3, u2);
						fp_exp_z(u3, u3);
						fp_exp_z(u3, u3);
						fp_mul(u1, u2, u3);
						fp_exp_z(u2, u3);
						fp_mul(u0, u0, u2);
						fp_copy(a, u0);
						fp_copy(c, u1);
					}
				//#endif
				break;

			case EP_B48:
				if (bn_sign(n) == RLC_NEG){
					bn_neg(n, n);
					fp_sqr(u0, b);
					fp_exp_z(u1, b);
					fp_exp_z(u2, u1);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_mul(u0, u0, u2);
					fp_exp_z(u2, u2);
					fp_mul(u0, u0, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u2, u2);
					fp_exp_z(u3, u2);
					fp_mul(u1, u1, u2);
					fp_mul(u1, u1, u3);
					fp_copy(a, u0);
					fp_copy(c, u1);
				}
				else {
					fp_sqr(u0, b);
					fp_exp_z(u1, b);
					fp_mul(u0, u0, u1);
					fp_exp_z(u1, u1);
					fp_exp_z(u1, u1);
					fp_exp_z(u1, u1);
					fp_exp_z(u1, u1);
					fp_exp_z(u1, u1);
					fp_exp_z(u1, u1);
					fp_exp_z(u1, u1);
					fp_mul(u0, u0, u1);
					fp_exp_z(u2, u1);
					fp_exp_z(u3, u2);
					fp_exp_z(u3, u3);
					fp_exp_z(u3, u3);
					fp_exp_z(u3, u3);
					fp_exp_z(u3, u3);
					fp_exp_z(u3, u3);
					fp_exp_z(u3, u3);
					fp_mul(u1, u2, u3);
					fp_exp_z(u2, u3);
					fp_mul(u0, u0, u2);
					fp_copy(a, u0);
					fp_copy(c, u1);
				}
				break;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		fp_free(u0);
		fp_free(u1);
		fp_free(u2);
		fp_free(u3);
	}
}


void tate_exp2(fp_t a, fp_t b){
	bn_t n, p;
	fp_t c;
	bn_null(n);
	bn_null(p);
	fp_null(c);
	RLC_TRY {
		bn_new(n);
		bn_new(p);
		fp_new(c);
		p->used = RLC_FP_DIGS;
		dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(p, p, 1);
		fp_prime_get_par(n);
		switch (ep_curve_is_pairf()){
			case EP_B12:
			case EP_B24:
			case EP_B48:
				bn_sub_dig(n, n, 1);
				bn_div(n, p, n);
				if (bn_sign(n) == RLC_NEG)bn_neg(n, n);
				fp_exp(c, b, n);
				fp_copy(a, c);
				break;
			case EP_BW13:
				bn_t u;
				bn_sqr(u, n);
				bn_sub(n, u, n);	
				bn_add_dig(n, n, 1);
				bn_div(n, p, n);
				fp_exp(c, b, n);
				fp_copy(a, c);
				break;		
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(p);
		fp_free(c);
	}
}