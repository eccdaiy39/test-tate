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

#include "relic_pc.h"
#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Internal macro to map GT function to basic FPX implementation. The final
 * exponentiation from the pairing is used to move element to subgroup.
 *
 * @param[out] A 				- the element to assign.
 */
#define gt_rand_imp(A)			RLC_CAT(RLC_GT_LOWER, rand)(A)

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void gt_rand(gt_t a) {
	gt_rand_imp(a);
#if FP_PRIME < 1536
#if FP_PRIME == 315 || FP_PRIME == 317 || FP_PRIME == 509
	pp_exp_k24(a, a);
#elif FP_PRIME == 638 && !defined(FP_QNRES)
	pp_exp_k18(a, a);
#else
	pp_exp_k12(a, a);
#endif
#else
	pp_exp_k2(a, a);
#endif
}

void gt_get_gen(gt_t g) {
    gt_copy(g, core_get()->gt_g);
}

int g1_is_valid(const g1_t a) {
	bn_t n, t;
	g1_t u, v;
	size_t l0, l1, r = 0;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1];

	if (g1_is_infty(a)) {
		return 0;
	}

	bn_null(n);
	bn_null(t);
	g1_null(u);
	g1_null(v);

	RLC_TRY {
		bn_new(n);
		bn_new(t);
		g1_new(u);
		g1_new(v);

		ep_curve_get_cof(n);
		if (bn_cmp_dig(n, 1) == RLC_EQ) {
			/* If curve has prime order, simpler to check if point on curve. */
			r = g1_on_curve(a);
		} else {
			fp_prime_get_par(n);
			switch (ep_curve_is_pairf()) {
				/* Formulas from "Co-factor clearing and subgroup membership
				 * testing on pairing-friendly curves" by El Housni, Guillevic,
				 * Piellard. https://eprint.iacr.org/2022/352.pdf */
				case EP_B12:
				case EP_B24:
				case EP_B48:
					/* Check [\psi^2(P) == [-z^2]P. */
					g1_mul_any(u, a, n);
					g1_mul_any(u, u, n);
					if (ep_curve_is_pairf() == EP_B24) {
						/* Check [\psi^2(P) == [-z^4]P. */
						g1_mul_any(u, u, n);
						g1_mul_any(u, u, n);
					}
					if (ep_curve_is_pairf() == EP_B48) {
						/* Check [\psi^2(P) == [-z^8]P. */
						g1_mul_any(u, u, n);
						g1_mul_any(u, u, n);
						g1_mul_any(u, u, n);
						g1_mul_any(u, u, n);
					}
					g1_neg(u, u);
					ep_psi(v, a);
					ep_psi(v, v);
					r = g1_on_curve(a) && (g1_cmp(v, u) == RLC_EQ);
					break;
				case EP_K18:
					/* Check that [a_0]P + [a_1]\psi(P)) == O, for
					 * a_0 = 19a_1 + 1, a_1 = (x/7)^3 */
					fp_prime_get_par(n);
					bn_div_dig(n, n, 7);
					bn_sqr(t, n);
					bn_mul(n, n, t);
					bn_mul_dig(t, n, 19);
					bn_add_dig(t, t, 1);
					ep_psi(v, a);

					l0 = l1 = RLC_FP_BITS + 1;
					bn_rec_naf(naf0, &l0, t, 2);
					bn_rec_naf(naf1, &l1, n, 2);

					ep_copy(u, a);
					for (int i = RLC_MAX(l0, l1) - 2; i >= 0; i--) {
						g1_dbl(u, u);
						if (naf0[i] > 0) {
							g1_add(u, u, a);
						}
						if (naf0[i] < 0) {
							g1_sub(u, u, a);
						}
						if (naf1[i] > 0) {
							g1_add(u, u, v);
						}
						if (naf1[i] < 0) {
							g1_sub(u, u, v);
						}
					}
					if (bn_sign(n) == RLC_NEG) {
						g1_neg(u, u);
					}
					r = g1_on_curve(a) && g1_is_infty(u);
					break;
				default:
					pc_get_ord(n);
					bn_sub_dig(n, n, 1);
					/* Otherwise, check order explicitly. */
					/* We use fast scalar multiplication methods here, because
					 * they should work only in the correct subgroup. */
					g1_mul(u, a, n);
					g1_neg(u, u);
					r = g1_on_curve(a) && (g1_cmp(u, a) == RLC_EQ);
					break;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(t);
		g1_free(u);
		g1_free(v);
	}

	return r;
}

int g2_is_valid(const g2_t a) {
#if FP_PRIME >= 1536
	if (pc_map_is_type1()) {
		return g1_is_valid(a);
	}
#else

	if (g2_is_infty(a)) {
		return 0;
	}

	bn_t p, n;
	g2_t u, v;
	int r = 0;

	bn_null(n);
	bn_null(p);
	g2_null(u);
	g2_null(v);

	RLC_TRY {
		bn_new(n);
		bn_new(p);
		g2_new(u);
		g2_new(v);

		pc_get_ord(n);
		ep_curve_get_cof(p);

		if (bn_cmp_dig(p, 1) == RLC_EQ) {
			/* Trick for curves of prime order or subgroup-secure. */
			bn_mul(n, n, p);
			dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
			p->used = RLC_FP_DIGS;
			p->sign = RLC_POS;
			/* Compute trace t = p - n + 1. */
			bn_sub(n, p, n);
			bn_add_dig(n, n, 1);
			g2_mul_any(u, a, n);
			/* Compute v = a^(p + 1). */
			g2_frb(v, a, 1);
			g2_add(v, v, a);
			/* Check if a^(p + 1) = a^t. */
			r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
		} else {
			switch (ep_curve_is_pairf()) {
				/* Formulas from "Co-factor clearing and subgroup membership
				 * testing on pairing-friendly curves" by El Housni, Guillevic,
				 * Piellard. https://eprint.iacr.org/2022/352.pdf */
				case EP_B12:
				case EP_B24:
					if (core_get()->ep_id == B12_383) {
						/* Since p mod n = r, we can check instead that
						 * psi^4(P) + P == \psi^2(P). */
						g2_frb(u, a, 4);
						g2_add(u, u, a);
						g2_frb(v, a, 2);
					} else {
						/* Check \psi(P) == [z]P. */
						fp_prime_get_par(n);
						g2_mul_any(u, a, n);
						g2_frb(v, a, 1);
					}
					r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
					break;
				/* Formulas from "Fast Subgroup Membership Testings for G1,
				 * G2 and GT on Pairing-friendly Curves" by Dai et al.
				 * https://eprint.iacr.org/2022/348.pdf */
				case EP_K18:
					/* Check that [2z/7]P + \psi(P) + [z/7]\psi^3(P) == O. */
					fp_prime_get_par(n);
					bn_div_dig(n, n, 7);
					g2_mul_any(u, a, n);
					g2_frb(v, u, 2);
					g2_dbl(u, u);
					g2_add(v, v, a);
					g2_frb(v, v, 1);
					g2_neg(v, v);
					r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
					break;
				default:
					pc_get_ord(n);
					bn_sub_dig(n, n, 1);
					/* Otherwise, check order explicitly. */
					/* We use fast scalar multiplication methods here, because
					 * they should work only in the correct order. */
					g2_mul(u, a, n);
					g2_neg(u, u);
					r = g2_on_curve(a) && (g2_cmp(u, a) == RLC_EQ);
					break;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(p);
		bn_free(n);
		g2_free(u);
		g2_free(v);
	}

	return r;
#endif
}

int gt_is_valid(const gt_t a) {
	bn_t p, n;
	gt_t u, v;
	int l, r = 0;
	const int *b;

	if (gt_is_unity(a)) {
		return 0;
	}

	bn_null(n);
	bn_null(p);
	gt_null(u);
	gt_null(v);

	RLC_TRY {
		bn_new(n);
		bn_new(p);
		gt_new(u);
		gt_new(v);

		pc_get_ord(n);
		ep_curve_get_cof(p);

		/* For a BN curve, we can use the fast test from
		 * Unbalancing Pairing-Based Key Exchange Protocols by Scott.
		 * https://eprint.iacr.org/2013/688.pdf */
		if (bn_cmp_dig(p, 1) == RLC_EQ) {
			dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
			p->used = RLC_FP_DIGS;
			p->sign = RLC_POS;
			if (ep_curve_is_pairf() == EP_BN) {
				/* Compute trace t = p - n + 1, and compute a^t. */
				fp_prime_get_par(n);
				b = fp_prime_get_par_sps(&l);
				fp12_exp_cyc_sps((void *)v, (void *)a, b, l, RLC_POS);
				fp12_exp_cyc_sps((void *)u, (void *)v, b, l, RLC_POS);
				gt_sqr(v, u);
				gt_sqr(u, v);
				gt_mul(u, u, v);
			} else {
				/* Compute trace t = p - n + 1. */
				bn_sub(n, p, n);
				/* Compute u = a^t. */
				gt_exp(u, a, n);
			}
			/* Compute v = a^(p + 1). */
			gt_frb(v, a, 1);
			/* Check if a^(p + 1) = a^t. */
			r = fp12_test_cyc((void *)a) && (gt_cmp(u, v) == RLC_EQ);
		} else {
			fp_prime_get_par(n);
			b = fp_prime_get_par_sps(&l);
			switch (ep_curve_is_pairf()) {
				/* Formulas from "Families of SNARK-friendly 2-chains of
				 * elliptic curves" by Housni and Guillevic.
				 * https://eprint.iacr.org/2021/1359.pdf */
				case EP_B12:
					if (core_get()->ep_id == B12_383) {
						/* GT-strong, so test for cyclotomic only. */
						r = 1;
					} else {
						/* Check that a^u = a^p. */
						gt_frb(u, a, 1);
						fp12_exp_cyc_sps((void *)v, (void *)a, b, l, bn_sign(n));
						r = (gt_cmp(u, v) == RLC_EQ);
					}
					r &= fp12_test_cyc((void *)a);
					break;
				case EP_B24:
					/* Check that a^u = a^p. */
					gt_frb(u, a, 1);
					fp24_exp_cyc_sps((void *)v, (void *)a, b, l, bn_sign(n));
					r = (gt_cmp(u, v) == RLC_EQ);
					r &= fp24_test_cyc((void *)a);
					break;
				/* Formulas from "Fast Subgroup Membership Testings for G1,
				 * G2 and GT on Pairing-friendly Curves" by Dai et al.
				 * https://eprint.iacr.org/2022/348.pdf */
				case EP_K18:
					/* Check that [2z]P + [z]\psi^3(P) == -7\psi(P). */
					fp18_exp_cyc_sps((void *)u, (void *)a, b, l, bn_sign(n));
					gt_frb(v, u, 3);
					gt_sqr(u, u);
					gt_mul(u, u, v);
					gt_sqr(v, a);
					gt_mul(v, v, a);
					gt_sqr(v, v);
					gt_mul(v, v, a);
					gt_frb(v, v, 1);
					gt_inv(v, v);
					r = (gt_cmp(u, v) == RLC_EQ);
					r &= fp18_test_cyc((void *)a);
					break;
				default:
					/* Common case. */
					bn_sub_dig(n, n, 1);
					gt_exp(u, a, n);
					gt_inv(u, u);
					r = (gt_cmp(u, a) == RLC_EQ);
					break;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(p);
		bn_free(n);
		gt_free(u);
		gt_free(v);
	}

	return r;
}

int g2_is_valid_bn(const g2_t a) {


	if (g2_is_infty(a)) {
		return 0;
	}

	bn_t  n;
	g2_t u0, u1, u2, u3;
	int r = 0;

	bn_null(n);
	g2_null(u0);
	g2_null(u1);
	g2_null(u2);
	g2_null(u3);
	RLC_TRY {
		bn_new(n);
		g2_new(u0);
		g2_new(u1);
		g2_new(u2);
		g2_new(u3);

       		 fp_prime_get_par(n);

		/* Compute v = a^(n+1)*a^(np)*a^(np^2) and a^(np^3). */
			g2_copy(u1, a);
			for (int i = bn_bits(n) - 2; i >= 0; i--) {
				g2_dbl(u1, u1);
				if (bn_get_bit(n, i)) {
					g2_add(u1, u1, a);
				}
			}
		if (bn_sign(n) == RLC_NEG) {
			g2_neg(u1, u1);
			}
		g2_add(u0, u1, a);
		g2_dbl(u3, u1);
		g2_frb(u2, u1, 2);
		g2_frb(u1, u1, 1);
		g2_frb(u3, u3, 3);
		g2_add(u0, u0, u1);
		g2_add(u0, u0, u2);
		/* Check that u0 = u3. */
		r = g2_on_curve(a) && (g2_cmp(u0, u3) == RLC_EQ);
		} 	
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(p);
		bn_free(n);
		g2_free(u0);
		g2_free(u1);
		g2_free(u2);
		g2_free(u3);
	}
	return r;
}

int gt_is_valid_bn(gt_t a) {
	bn_t p, n;
	gt_t u, v, y, w;
	int l, r = 0;
	const int *b;

	if (gt_is_unity(a)) {
		return 0;
	}

	bn_null(n);
	bn_null(p);
	gt_null(u);
	gt_null(v);
	gt_null(r);
	gt_null(w);

	RLC_TRY {
		bn_new(n);
		bn_new(p);
		gt_new(u);
		gt_new(v);
		gt_null(r);
		gt_null(w);


		pc_get_ord(n);
		ep_curve_get_cof(p);
			dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
			p->used = RLC_FP_DIGS;
			p->sign = RLC_POS;
			fp_prime_get_par(n);
			b = fp_prime_get_par_sps(&l);
			fp12_exp_cyc_sps((void *)v, (void *)a, b, l, RLC_POS);
			gt_sqr(u, v);
			gt_mul(y, u, a);
			/* Compute v = a^(p + 1). */
			gt_frb(w, v, 1);
			gt_frb(v, v, 2);
			gt_frb(u, u, 3);
			gt_mul(v, v, y);
			gt_mul(v, v, w);
			/* Check if a^(p + 1) = a^t. */
			r = fp12_test_cyc((void *)a) && (gt_cmp(u, v) == RLC_EQ);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(p);
		bn_free(n);
		gt_free(u);
		gt_free(v);
		gt_free(r);
		gt_free(w);


	}
	return r;
}
int g1_is_valid_bw13(ep_t a) {
	bn_t  n;
	ep_t u0, u1, u2;
	int r = 0;

	if (ep_is_infty(a)) {
		return 0;
	}

	bn_null(n);
	ep_null(u0);
	ep_null(u1);
	ep_null(u2);
	RLC_TRY {
		bn_new(n);
		ep_new(u0);
		ep_new(u1);
		ep_new(u2);

		/*[a0,a1]=[−(z^7 + z)(z^4 + z^3 − z − 1),a0 · z − 1]*/
		/*checking a0*a+a1*psi(a)=0, where psi() is a GLV endorphism*/
		fp_prime_get_par(n);
		ep_mul_basic(u0, a, n);
		ep_mul_basic(u1, u0, n);
		ep_mul_basic(u1, u1, n);
		ep_mul_basic(u2, u1, n);
		ep_add(u0, u0, a);
		ep_add(u1, u1, u2);
		ep_sub(u0, u1, u0);
		ep_mul_basic(u0, u0, n);
		ep_mul_basic(u1, u0, n);
                for(int i = 0; i < 5; i++)ep_mul_basic(u1, u1, n);
		ep_add(u0, u0, u1);
		ep_neg(u0, u0);

		ep_mul_basic(u1, u0, n);
		ep_sub(u1, a, u1);
           	ep_psi(u1, u1);

		r = (ep_on_curve(a)) && (ep_cmp(u0,u1) == RLC_EQ);
		} 	
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		ep_free(u0);
		ep_free(u1);
		ep_free(u2);

	}
	return r;
}

int g2_is_valid_bw13(ep13_t a) {

	ep13_t u0, u1, v0, v1, v2, v3;
	int r = 0;
	if (ep13_is_infty(a)) {
		return 0;
	}


	ep13_null(u0);
	ep13_null(u1);
	ep13_null(v0);
	ep13_null(v1);
	ep13_null(v2);
	ep13_null(v3);
	RLC_TRY {
		ep13_new(u0);
		ep13_new(u1);
		ep13_new(v0);
		ep13_new(v1);
		ep13_new(v2);
		ep13_new(v3);

		/*cheking psi(a)=-z*a, where psi()  is a 24-dimensional endormphism*/
		ep13_rand_mul_u(u0, a);
		ep13_neg(u0, u0);
                ep13_psi(u1, a, 1);

		/*cheking a is a element of the trace zero subgroup*/
 		ep13_frb(v0, a, 1);
 		ep13_frb(v1, a, 2);
                ep13_add(v0, v0, v1);
		ep13_frb(v1, v0, 2);
		ep13_add(v1, v0, v1);
		ep13_frb(v2, v1, 4);
		ep13_frb(v3, v2, 4);		
		ep13_add(v0, v1, v2);
		ep13_add(v0, v0, v3);
		ep13_neg(v1, a);
           
		r = ep13_on_curve(a) && (ep13_cmp(u0, u1) == RLC_EQ) && (ep13_cmp(v0, v1) == RLC_EQ);

		} 	
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep13_free(u0);
		ep13_free(u1);
		ep13_free(v0);
		ep13_free(v1);
		ep13_free(v2);
		ep13_free(v3);
	}
	return r;
}

int gt_is_valid_bw13(fp13_t a) {
	bn_t  n;
	fp13_t u0, u1, u2, u3;
	int r = 0;

	if (fp13_is_zero(a)||(fp13_cmp_dig(a,1) == RLC_EQ)) {
		return 0;
	}

	bn_null(n);
	fp13_null(u0);
	fp13_null(u1);
	fp13_null(u2);
	fp13_null(u3);
	RLC_TRY {
		bn_new(n);
		fp13_new(u0);
		fp13_new(u1);
		fp13_new(u2);
		fp13_new(u3);
		fp_prime_get_par(n);
		bn_neg(n,n);

		/*checking a is a element of cyclotomic subgroup of F^13_{p}*/
		fp13_frb(u1, a, 1);
		fp13_frb(u2, a, 2);
		fp13_mul(u1, u1, u2);
		fp13_frb(u2, u1, 2);
		fp13_mul(u1, u1, u2);

		fp13_frb(u2, u1, 4);
		fp13_frb(u0, u2, 4);	
		fp13_mul(u1, u0, u1);	
		fp13_mul(u1, u1, u2);
		fp13_mul(u1, u1, a);

	        /*the vector C is selected as [z^2, -z, 1]. Checking a^(z^2-z*p+p^2)=1*/
           	fp13_exp(u0, a, n);
		fp13_exp(u3, u0, n);
		fp13_frb(u0, u0, 1);
		fp13_frb(u2, a, 2);
		fp13_mul(u0, u0, u3);
		fp13_mul(u0, u0, u2);
	
		r =  (fp13_cmp_dig(u0,1) == RLC_EQ) && (fp13_cmp_dig(u1,1) == RLC_EQ);

		} 	
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		fp13_free(u0);
		fp13_free(u1);
		fp13_free(u2);
		fp13_free(u3);

	}
	return r;
}

