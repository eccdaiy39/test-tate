# revisiting subgroup membership testing on pairing-friendly curves via the Tate pairing 
### Notice
Please make sure that the name of the  downloaded file does not contain "()", eg.<******(1)>.
Otherwise, the code can not be complied at the "cmake" step. 

### Requirements

The build process requires the [CMake](https://cmake.org/) cross-platform build system. The [GMP](https://gmplib.org/) library is also needed in our benchmarks.

### Build instructions

Instructions for building the library can be found in the [Wiki](https://github.com/relic-toolkit/relic/wiki/Building).


### Source code
  
The main source code of our algorithms are distributed in different folders.  The main functions are:

// in "relic-test-tate/src/pc/relic_pc_tate.c"
* void g1_tate_gen(g1_t g): generating an auxiliary point that is required for computing two small Tate pairings.
* int g1_is_valid_tate(g1_t a, g1_t q): on input the candidate point a and the auxiliary point, checking whether a is valid or not.
* int test_tate(g1_t p, g1_t q): computing the two Tate pairings f1=e(q,p) and f2=e(q,\phi\hat(p)), if f1=f2=1 then return RLC_EQ; otherwise, return RLC_NE; 
* void tate_miller(fp_t N1, fp_t D1, fp_t N2, fp_t D2, g1_t q, g1_t p, g1_t p2): given a random point p, p2=\hat\phi(p) and the  auxiliary point q, computing N1,D1, N2, D2 such that f_{m, q}(p)=N1/D1 and f_{m, q}(p2)=N2/D2;
* void miller_tab(fp_t *tab, g1_t q): given the auxiliary point q, generating a lookup table tab that can be used for speed up pairing computation with precomputation;
* void tate_miller_pre(fp_t *tab, fp_t N1, fp_t D1, fp_t N2, fp_t D2, g1_t q, g1_t p, g1_t p2):  given a random point p, p2=\hat\phi(p) and a auxiliary point q, a lookup table tab,  computing N1,D1, N2, D2 such that f_{m, q}(p)=N1/D1 and f_{m, q}(p2)=N2/D2  with precomputation;
* int test_tate_pre(g1_t p, g1_t q, fp_t *tab): given a random point p, p2=\hat\phi(p), a auxiliary point q and a lookup table tab,   computing the two Tate pairings f1=e(q,p) and f2=e(q,\phi\hat(p)). If f1=f2=1 then return RLC_EQ; otherwise, return RLC_NE; 
* int g1_is_valid_tate_pre(g1_t a, g1_t q, fp_t* tab):  on input a candidate point a,  a auxiliary point q and a lookup table tab, checking whether a is valid or not.

// in "relic-test-tate/src/pc/relic_pc_qpl.c"
* void tate_qpl(fp_t f1, fp_t g1, fp_t f2, fp_t g2, g1_t q, g1_t p, g1_t p2): the SQPL step;
* void tate_dba(fp_t f1, fp_t g1, fp_t f2, fp_t g2,  g1_t r, g1_t q, g1_t p, g1_t p2): the SDADD step;
* void tate_add(fp_t f1, fp_t g1, fp_t f2, fp_t g2, g1_t r, g1_t q, g1_t p, g1_t p2): the SADD step;
* void tate_sub(fp_t f1, fp_t g1, fp_t f2, fp_t g2, g1_t r, g1_t q, g1_t p, g1_t p2): the SSUB step;
* void tate_dbl(fp_t f1, fp_t g1, fp_t f2, fp_t g2, g1_t q, g1_t p, g1_t p2): the SDBL step;
* void tate_dbs(fp_t f1, fp_t g1, fp_t f2, fp_t g2,  g1_t r, g1_t q, g1_t p, g1_t p2): the SDSUB step;

// in "relic-test-tate/src/pc/relic_pc_exp.c"
* void tate_exp1(fp_t a, fp_t c, fp_t b): given b in Fp, computing a and c such that a/c=b^e1, where e1 is the final exponent of the first Tate pairing;
* void tate_exp2(fp_t a, fp_t b): given b in Fp, computing b^e2, where e2 is the final exponent of the second Tate pairing;

// in "relic-test-tate/src/fp/relic_fp_exp.c"
* void fp_exp_z(fp_t a, const fp_t b): given b in Fp, computing a=b^z, where z is the seed of pairing -friendly curves.

### Testings, benckmarks and comparisons
* Testings and benckmarks for BW13-310:  testings and benckmarking can be done by performing the following commands：

    1. mkdir build && cd build 
    2. ../preset/x64-pbc-bw310.sh ../
    3. make
    4. cd bin 
    5. ./test_bw13  (This is to check that our implementation is corrret)
    6. ./bench_pc_bw13 (This is to obtain clock cycles of involved operations on BW13-P310)
  
* Testings and benckmarks for BLS12-381, BLS12-446, BLS24-351, BLS24-509 and BLS48-575:  testings and benckmarking can be done by performing the following commands：

   1. mkdir build && cd build 
   2. ../preset/ < preset >.sh ../
   3. make
   4. cd bin 
   5. ./bench_pc
