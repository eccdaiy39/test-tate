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
#include"relic_fp_low.h"
#include "relic_util.h"

void tate_qpl(fp_t f1, fp_t g1, fp_t f2, fp_t g2, g1_t q, g1_t p, g1_t p2){
	fp_t t0, tt0, t1, t2, t3, t4, t5;
	dv_t u0, u1, u2;
	g1_t _q;
	fp_null(t0);
	fp_null(tt0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);
	dv_null(u0);
	dv_null(u1);
	dv_null(u2);

	RLC_TRY {
		fp_new(t0);
		fp_new(tt0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		dv_new(u0);
		dv_new(u1);
		dv_new(u2);
		g1_copy(_q,q);
		
		/*compute [4]*q and q<-[4]*q*/

		//doubling point 
		fp_sqr(t0, _q->x);
		fp_hlv(t1, t0);
		fp_add(t0, t0, t1);
		fp_sqr(t1, t0);
		fp_sqr(t2, _q->y);
		fp_mul(t3, _q->x, t2);
		fp_dbl(t4, t3);
		fp_sub(_q->x, t1, t4);

		fp_mul(_q->z, _q->y, _q->z);

		fp_sub(t1, t3, _q->x);
		fp_muln_low(u0, t0, t1);
		fp_sqrn_low(u1, t2);
		fp_subc_low(u0, u0, u1);
		fp_rdc(_q->y, u0);

		
		//quadrupling point
		fp_sqr(tt0, _q->x);
		fp_hlv(t1, tt0);
		fp_addn_low(tt0, tt0, t1);//
		fp_sqr(t1, tt0);
		fp_sqr(t2, _q->y);//
		fp_mul(t3, _q->x, t2);//
		fp_dbl(t4, t3);
		fp_sub(q->x, t1, t4);
		fp_mul(q->z, _q->y, _q->z);

		fp_sub(t1, t3, q->x);
		fp_muln_low(u0, tt0, t1);
		fp_sqrn_low(u1, t2);
		fp_subc_low(u0, u0, u1);
		fp_rdc(q->y, u0);
		
        	/*line functions*/
		fp_sqr(t1, _q->z);//A
		fp_mul(t3, t1, q->z);//B
		fp_muln_low(u0, t3, p->y);//U0
		fp_mul(t4, t1, p->x);
		fp_mul(t5, t1, p2->x);
		fp_sub(t4, t4, _q->x);//C
		fp_sub(t5, t5, _q->x);//D

		fp_mul(t0, t0, _q->y);//E
		fp_muln_low(u1, t0, t4);//U3
		fp_muln_low(u2, tt0, t4);//U1
		fp_addc_low(u1, u0, u1);//H
		fp_subc_low(u2, u0, u2);//F
		fp_rdc(t1, u1);//H
		fp_rdc(t4, u2);//F
		fp_sub(g1, t1, t2);//H-Y^2_2T
		fp_sub(f1, t4, t2);
		fp_mul(f1, f1, t3);//(F-Y^2_2T)B



		fp_muln_low(u1, t0, t5);//U4
		fp_muln_low(u2, tt0, t5);//U2
		fp_addc_low(u1, u0, u1);
		fp_subc_low(u2, u0, u2);
		fp_rdc(t1, u1);//I
		fp_rdc(t4, u2);//G
		fp_sub(g2, t1, t2);//I-Y^2_2T
		fp_sub(f2, t4, t2);
		fp_mul(f2, f2, t3);//(G-Y^2_2T)B
               
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(tt0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);  


		dv_free(u0);
		dv_free(u1);
		dv_free(u2);
	}
}

void tate_dba(fp_t f1, fp_t g1, fp_t f2, fp_t g2,  g1_t r, g1_t q, g1_t p, g1_t p2) {
	fp_t t0, tt0, t1, tt1, t2, t3, t4, t5;
	dv_t u0, u1, u2;
	g1_t _q;
	fp_null(t0);
	fp_null(tt0);
	fp_null(t1);
	fp_null(tt1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);
	dv_null(u0);
	dv_null(u1);
	dv_null(u2);

	RLC_TRY {
		fp_new(t0);
		fp_new(tt0);
		fp_new(t1);
		fp_new(tt1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		fp_new(t5);
		dv_new(u0);
		dv_new(u1);
		dv_new(u2);
		g1_copy(_q,r);
		
		/*compute [2]*q and q<-[2]*q+r*/

		//doubling point 
		fp_sqr(t0, _q->x);
		fp_hlv(t1, t0);
		fp_addn_low(t0, t0, t1);//
		fp_sqr(t1, t0);
		fp_sqr(t2, _q->y);
		fp_mul(t3, _q->x, t2);
		fp_dbl(t4, t3);
		fp_sub(_q->x, t1, t4);
		fp_mul(_q->z, _q->y, _q->z);

		fp_sub(t1, t3, _q->x);
		fp_muln_low(u0, t0, t1);
		fp_sqrn_low(u1, t2);
		fp_subc_low(u0, u0, u1);
		fp_rdc(_q->y, u0);
		
		//addition point

		fp_sqr(t5, _q->z);//
		fp_mul(tt1, _q->z, t5);  
		fp_mul(t2, tt1, q->y);	
		fp_sub(t1, t2, _q->y);//a
		fp_mul(tt0, t5, q->x);
		fp_sub(tt0, tt0, _q->x);//b
		fp_sqr(t2, tt0);//b^2
		fp_mul(t3, t2, tt0);//b^3
		fp_sqr(t4, t1);//a^2
		fp_sub(t4, t4, t3);
		fp_mul(t2, _q->x, t2);
		fp_dbl(r->x, t2);
		fp_sub(r->x, t4, r->x);

		fp_muln_low(u0, _q->y, t3);
		fp_sub(t2, t2, r->x);
		fp_muln_low(u1, t2, t1);
		fp_subc_low(u1, u1, u0);
		fp_rdc(r->y, u1);
		fp_mul(r->z, _q->z, tt0);
	
		/*line functions*/
	
		fp_mul(t2, tt1, p->y);
		fp_sub(t2, t2, _q->y);
		fp_muln_low(u0, tt0, t2);//deta1
		fp_mul(t2, t5, p->x);
		fp_sub(t2, t2, _q->x);//deta2
		fp_muln_low(u1, t1, t2);
		fp_subc_low(u1, u0, u1);
		fp_rdc(f1, u1);

		fp_mul(t0, t0, tt0);
		fp_muln_low(u1,t0, t2);
		fp_addc_low(u1, u0, u1);
		fp_rdc(g1, u1);



		fp_mul(t2, t5, p2->x);
		fp_sub(t2, t2, _q->x);//deta2
		fp_muln_low(u1, t1, t2);
		fp_subc_low(u1, u0, u1);
		fp_rdc(f2, u1);

		fp_muln_low(u1, t0, t2);
		fp_addc_low(u1, u0, u1);
		fp_rdc(g2, u1);

		
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(tt0);
		fp_free(tt1);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);

		dv_free(u0);
		dv_free(u1);
		dv_free(u2);
	}
}
void tate_add(fp_t f1, fp_t g1, fp_t f2, fp_t g2, g1_t r, g1_t q, g1_t p, g1_t p2) {
	fp_t t0, tt0, tt1, t1, t2, t3, t4;
	dv_t u0, u1;
	g1_t _r;
	
	fp_null(t0);
	fp_null(tt0);
	fp_null(t1);
	fp_null(tt1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	dv_null(u0);
	dv_null(u1);


	RLC_TRY {
		fp_new(t0);
		fp_null(tt0);
		fp_new(t1);
		fp_null(tt1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		dv_new(u0);
		dv_new(u1);
		g1_copy(_r, r);
		
		/*compute q + r and r <- q + r */
		fp_sqr(t0, r->z);
		fp_mul(tt1, r->z, t0);  
		fp_mul(t2, tt1, q->y);	
		fp_sub(t1, t2, r->y);//sita
		fp_mul(tt0, t0, q->x);
		fp_sub(tt0, tt0, r->x);//lambda
		fp_sqr(t2, tt0);//lambda^2
		fp_mul(t3, t2, tt0);//lambda^3
		fp_sqr(t4, t1);
		fp_sub(t4, t4, t3);
		fp_mul(t2, r->x, t2);
		fp_dbl(r->x, t2);
		fp_sub(r->x, t4, r->x);
		fp_muln_low(u0, r->y, t3);
		fp_sub(t2, t2, r->x);
		fp_muln_low(u1, t2, t1);
		fp_subc_low(u1, u1, u0);
		fp_rdc(r->y, u1);
		fp_mul(r->z, r->z, tt0);
		
		/*compute the line functions*/
		fp_mul(tt1, tt1, p->y);
		fp_sub(tt1, tt1, _r->y);
		fp_muln_low(u0, tt0, tt1);

		fp_mul(t2, t0, p->x);
		fp_sub(t2, t2, _r->x);
		fp_muln_low(u1, t2, t1);
		fp_subc_low(u1, u0, u1);
		fp_rdc(f1, u1);
		fp_mul(g1, t2, r->z);


		fp_mul(t0, t0, p2->x);
		fp_sub(t0, t0, _r->x);
		fp_muln_low(u1, t0, t1);
		fp_subc_low(u0, u0, u1);
		fp_rdc(f2, u0);
		fp_mul(g2, t0, r->z);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
	        fp_free(tt0);
		fp_free(t1);
	        fp_free(tt1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);
		fp_free(t6);
		dv2_free(u0);
		dv2_free(u1);
	}
}

void tate_sub(fp_t f1, fp_t g1, fp_t f2, fp_t g2, g1_t r, g1_t q, g1_t p, g1_t p2) {
	fp_t t0, tt0, tt1, t1, t2, t3, t4;
	dv_t u0, u1;
	g1_t _r;
	
	fp_null(t0);
	fp_null(tt0);
	fp_null(t1);
	fp_null(tt1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	dv_null(u0);
	dv_null(u1);


	RLC_TRY {
		fp_new(t0);
		fp_null(tt0);
		fp_new(t1);
		fp_null(tt1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		dv_new(u0);
		dv_new(u1);
		g1_copy(_r, r);
		
		/*compute r-q and r <- r-q */
		fp_sqr(t0, r->z);
		fp_mul(tt1, r->z, t0);  
		fp_mul(t2, tt1, q->y);	
		fp_add(t1, t2, r->y);
		fp_neg(t1, t1);//sita
		fp_mul(tt0, t0, q->x);
		fp_sub(tt0, tt0, r->x);//lambda
		fp_sqr(t2, tt0);//lambda^2
		fp_mul(t3, t2, tt0);//lambda^3
		fp_sqr(t4, t1);
		fp_sub(t4, t4, t3);
		fp_mul(t2, r->x, t2);
		fp_dbl(r->x, t2);
		fp_sub(r->x, t4, r->x);
		fp_muln_low(u0, r->y, t3);
		fp_sub(t2, t2, r->x);
		fp_muln_low(u1, t2, t1);
		fp_subc_low(u1, u1, u0);
		fp_rdc(r->y, u1);
		fp_mul(r->z, r->z, tt0);
		
		/*compute the line functions*/
		fp_sqr(t0, r->z);
		fp_mul(f1, t0, p->x);
		fp_sub(f1, f1, r->x);
		
		fp_mul(f2, t0, p2->x);
		fp_sub(f2, f2, r->x);
		
		fp_sub(t0, p->y, q->y);
		fp_muln_low(u0, t0, r->z);
		
		fp_sub(t0, p->x, q->x);
		fp_muln_low(u1, t0, t1);
		fp_addc_low(u1, u0, u1);
		fp_rdc(t0, u1);
		fp_mul(g1, t0, r->z);
		
		fp_sub(t0, p2->x, q->x);

		fp_muln_low(u1, t0, t1);
		fp_addc_low(u0, u0, u1);
		fp_rdc(t0, u0);	
		fp_mul(g2, t0, r->z);		
		
		
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
	        fp_free(tt0);
		fp_free(t1);
	        fp_free(tt1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);
		fp_free(t6);
		dv2_free(u0);
		dv2_free(u1);
	}
}
void tate_dbl(fp_t f1, fp_t g1, fp_t f2, fp_t g2, g1_t q, g1_t p, g1_t p2){
	fp_t t0, t1, t2, t3, t4, t5;
	dv_t u0, u1, u2;
	g1_t _q;
	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);
	dv_null(u0);
	dv_null(u1);
	dv_null(u2);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		dv_new(u0);
		dv_new(u1);
		dv_new(u2);
		g1_copy(_q,q);
		
		/*compute [2]*q and q<-[2]*q*/

		//doubling point 
		fp_sqr(t0, _q->x);
		fp_hlv(t1, t0);
		fp_add(t5, t0, t1);
		fp_sqr(t1, t5);
		fp_sqr(t2, _q->y);
		fp_mul(t3, _q->x, t2);
		fp_dbl(t4, t3);
		fp_sub(_q->x, t1, t4);

		fp_mul(_q->z, _q->y, _q->z);

		fp_sub(t1, t3, _q->x);
		fp_muln_low(u0, t5, t1);
		fp_sqrn_low(u1, t2);
		fp_subc_low(u0, u0, u1);
		fp_rdc(_q->y, u0);
		g1_copy(q, _q);
		
        	/*line functions*/
        	fp_sqr(t0, q->z);//A
        	fp_mul(t2, t0, q->z);//B
        	fp_mul(t3, t0, p->x);
        	fp_sub(t3, t3, q->x);//C1
        	fp_mul(f1, t3, q->z);
        	
         	fp_mul(t4, t0, p2->x);
        	fp_sub(t4, t4, q->x);//C2
        	fp_mul(f2, t4, q->z);
        	
        	fp_muln_low(u0, t2, p->y);
        	fp_muln_low(u1, t5, t3);
        	fp_addc_low(u1, u0, u1);
        	fp_rdc(t3, u1);//E
        	fp_sub(g1, t3, q->y);
        	
        	fp_muln_low(u1, t5, t4);//U2
        	fp_addc_low(u1, u0, u1);
        	fp_rdc(t3, u1);//F
        	fp_sub(g2, t3, q->y);
        	
        	
        	       	
        	

	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);  


		dv_free(u0);
		dv_free(u1);
		dv_free(u2);
	}
}

void tate_dbs(fp_t f1, fp_t g1, fp_t f2, fp_t g2,  g1_t r, g1_t q, g1_t p, g1_t p2) {
	fp_t t0, tt0, t1, tt1, t2, t3, t4, t5;
	dv_t u0, u1, u2;
	g1_t _q;
	fp_null(t0);
	fp_null(tt0);
	fp_null(t1);
	fp_null(tt1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);
	dv_null(u0);
	dv_null(u1);
	dv_null(u2);

	RLC_TRY {
		fp_new(t0);
		fp_new(tt0);
		fp_new(t1);
		fp_new(tt1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		fp_new(t5);
		dv_new(u0);
		dv_new(u1);
		dv_new(u2);
		g1_copy(_q,r);
		
		/*compute [2]*q and q<-[2]*q+r*/

		//doubling point 
		fp_sqr(t0, _q->x);
		fp_hlv(t1, t0);
		fp_addn_low(t0, t0, t1);//
		fp_sqr(t1, t0);
		fp_sqr(t2, _q->y);
		fp_mul(t3, _q->x, t2);
		fp_dbl(t4, t3);
		fp_sub(_q->x, t1, t4);
		fp_mul(_q->z, _q->y, _q->z);

		fp_sub(t1, t3, _q->x);
		fp_muln_low(u0, t0, t1);
		fp_sqrn_low(u1, t2);
		fp_subc_low(u0, u0, u1);
		fp_rdc(_q->y, u0);
		
		//substraction point

		fp_sqr(t5, _q->z);//
		fp_mul(tt1, _q->z, t5);  //
		fp_mul(t2, tt1, q->y);	
		fp_add(t1, t2, _q->y);
		fp_neg(t1, t1);//sita
		fp_mul(tt0, t5, q->x);
		fp_sub(tt0, tt0, _q->x);//b
		fp_sqr(t2, tt0);//b^2
		fp_mul(t3, t2, tt0);//b^3
		fp_sqr(t4, t1);//a^2
		fp_sub(t4, t4, t3);
		fp_mul(t2, _q->x, t2);
		fp_dbl(r->x, t2);
		fp_sub(r->x, t4, r->x);

		fp_muln_low(u0, _q->y, t3);
		fp_sub(t2, t2, r->x);
		fp_muln_low(u1, t2, t1);
		fp_subc_low(u1, u1, u0);
		fp_rdc(r->y, u1);
		fp_mul(r->z, _q->z, tt0);
	
		/*line functions*/
	
		fp_mul(t2, t5, p->x);
		fp_sub(t2, t2, _q->x);//A1
		fp_mul(t4, t5, p2->x);
		fp_sub(t4, t4, _q->x);//A2
		fp_mul(tt1, tt1, p->y);
		fp_sub(tt1, tt1, _q->y);//B
		fp_mul(t0, t0, tt0);//C
		fp_muln_low(u0, tt1, tt0);
		fp_muln_low(u1, t2, t1);
		fp_subc_low(u1, u0,u1);
		fp_rdc(f1, u1);
		
		fp_muln_low(u1, t4, t1);
		fp_subc_low(u1, u0, u1);
		fp_rdc(f2, u1);
		fp_muln_low(u1, t0, t2);
		fp_addc_low(u1, u0, u1);
		fp_rdc(t2, u1);//E
		fp_sub(g1, p->x, q->x);
		fp_mul(g1, g1, t2);
		
		
		
		fp_muln_low(u1, t0, t4);
		fp_addc_low(u1, u0, u1);
		fp_rdc(t2, u1);//E
		fp_sub(g2, p2->x, q->x);
		fp_mul(g2, g2, t2);
				
		
				
	
		
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(tt0);
		fp_free(tt1);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);

		dv_free(u0);
		dv_free(u1);
		dv_free(u2);
	}
}
