/*
 * secp256k1_complete.c
 *
 *  Created on: 2018-01-21
 *      Author: malego
 */


#include "secp256k1_complete.h"
#include "timer.h"
#include "common.h"
#include "bitcoin_module.h"
#include "sha256.h"
#include "RIPEMD160.h"
#include <pthread.h>




void rand_privkey(unsigned char *privkey);
void *safe_calloc(size_t num, size_t size);
int secp256k1_selfcheck(secp256k1_context* ctx, secp256k1_ecmult_big_context* bmul, secp256k1_scratch *scr);
void secp256k1_init(secp256k1_context** ctx, secp256k1_ecmult_big_context** bmul, secp256k1_scratch **scr);
int full_stack_check(secp256k1_context* ctx, const secp256k1_ecmult_big_context *bmul, secp256k1_scratch *scr);


static void default_illegal_callback_fn(const char* str, void* data);
static void default_error_callback_fn(const char* str, void* data);
static void secp256k1_gej_double_var(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr);



static const secp256k1_callback default_illegal_callback = {default_illegal_callback_fn,NULL};
static const secp256k1_callback default_error_callback = {default_error_callback_fn,NULL};

const unsigned int test_qty = 1024;
const unsigned int batch_size = 256;
const unsigned int bmul_size  = 16;    // ecmult_big window size in bits
const unsigned char baseline_privkey[32] = {
    // generated using srand(31415926), first 256 calls of rand() & 0xFF
    0xb9, 0x43, 0x14, 0xa3, 0x7d, 0x33, 0x46, 0x16, 0xd8, 0x0d, 0x62, 0x1b, 0x11, 0xa5, 0x9f, 0xdd,
    0x13, 0x56, 0xf6, 0xec, 0xbb, 0x9e, 0xb1, 0x9e, 0xfd, 0xe6, 0xe0, 0x55, 0x43, 0xb4, 0x1f, 0x30
};

const unsigned char baseline_expected[65] = {
    0x04, 0xfa, 0xf4, 0x5a, 0x13, 0x1f, 0xe3, 0x16, 0xe7, 0x59, 0x78, 0x17, 0xf5, 0x32, 0x14, 0x0d,
    0x75, 0xbb, 0xc2, 0xb7, 0xdc, 0xd6, 0x18, 0x35, 0xea, 0xbc, 0x29, 0xfa, 0x5d, 0x7f, 0x80, 0x25,
    0x51, 0xe5, 0xae, 0x5b, 0x10, 0xcf, 0xc9, 0x97, 0x0c, 0x0d, 0xca, 0xa1, 0xab, 0x7d, 0xc1, 0xb3,
    0x40, 0xbc, 0x5b, 0x3d, 0xf6, 0x87, 0xa5, 0xbc, 0xe7, 0x26, 0x67, 0xfd, 0x6c, 0xe6, 0xc3, 0x66, 0x29
};

/** Generator for secp256k1, value 'g' defined in
 *  "Standards for Efficient Cryptography" (SEC2) 2.7.1.
 */
static const secp256k1_ge secp256k1_ge_const_g = SECP256K1_GE_CONST(
    0x79BE667EUL, 0xF9DCBBACUL, 0x55A06295UL, 0xCE870B07UL,
    0x029BFCDBUL, 0x2DCE28D9UL, 0x59F2815BUL, 0x16F81798UL,
    0x483ADA77UL, 0x26A3C465UL, 0x5DA4FBFCUL, 0x0E1108A8UL,
    0xFD17B448UL, 0xA6855419UL, 0x9C47D08FUL, 0xFB10D4B8UL
);

pthread_mutex_t initMutex = PTHREAD_MUTEX_INITIALIZER;



#if defined(USE_FIELD_10X26)
#include "field_10x26_impl.h"
#elif defined(USE_FIELD_5X52)
#include "field_5x52_impl.h"
#else
#error "Please select field implementation"
#endif

#if defined(USE_SCALAR_4X64)
#include "scalar_4x64_impl.h"
#elif defined(USE_SCALAR_8X32)
#include "scalar_8x32_impl.h"
#else
#error "Please select scalar implementation"
#endif


static SECP256K1_INLINE void secp256k1_callback_call(const secp256k1_callback * const cb, const char * const text) {
    cb->fn(text, (void*)cb->data);
}

static SECP256K1_INLINE void *checked_malloc(const secp256k1_callback* cb, size_t size) {
    void *ret = malloc(size);
    if (ret == NULL) {
        secp256k1_callback_call(cb, "Out of memory");
    }
    return ret;
}

static void secp256k1_ge_set_gej_zinv(secp256k1_ge *r, const secp256k1_gej *a, const secp256k1_fe *zi) {
    secp256k1_fe zi2;
    secp256k1_fe zi3;
    secp256k1_fe_sqr(&zi2, zi);
    secp256k1_fe_mul(&zi3, &zi2, zi);
    secp256k1_fe_mul(&r->x, &a->x, &zi2);
    secp256k1_fe_mul(&r->y, &a->y, &zi3);
    r->infinity = a->infinity;
}

/** Fill a table 'prej' with precomputed odd multiples of a. Prej will contain
 *  the values [1*a,3*a,...,(2*n-1)*a], so it space for n values. zr[0] will
 *  contain prej[0].z / a.z. The other zr[i] values = prej[i].z / prej[i-1].z.
 *  Prej's Z values are undefined, except for the last value.
 */
static void secp256k1_ecmult_odd_multiples_table(int n, secp256k1_gej *prej, secp256k1_fe *zr, const secp256k1_gej *a) {
    secp256k1_gej d;
    secp256k1_ge a_ge, d_ge;
    int i;

    VERIFY_CHECK(!a->infinity);

    secp256k1_gej_double_var(&d, a, NULL);

    /*
     * Perform the additions on an isomorphism where 'd' is affine: drop the z coordinate
     * of 'd', and scale the 1P starting value's x/y coordinates without changing its z.
     */
    d_ge.x = d.x;
    d_ge.y = d.y;
    d_ge.infinity = 0;

    secp256k1_ge_set_gej_zinv(&a_ge, a, &d.z);
    prej[0].x = a_ge.x;
    prej[0].y = a_ge.y;
    prej[0].z = a->z;
    prej[0].infinity = 0;

    zr[0] = d.z;
    for (i = 1; i < n; i++) {
        secp256k1_gej_add_ge_var(&prej[i], &prej[i-1], &d_ge, &zr[i]);
    }

    /*
     * Each point in 'prej' has a z coordinate too small by a factor of 'd.z'. Only
     * the final point's z coordinate is actually used though, so just update that.
     */
    secp256k1_fe_mul(&prej[n-1].z, &prej[n-1].z, &d.z);
}

/** Fill a table 'pre' with precomputed odd multiples of a.
 *
 *  There are two versions of this function:
 *  - secp256k1_ecmult_odd_multiples_table_globalz_windowa which brings its
 *    resulting point set to a single constant Z denominator, stores the X and Y
 *    coordinates as ge_storage points in pre, and stores the global Z in rz.
 *    It only operates on tables sized for WINDOW_A wnaf multiples.
 *  - secp256k1_ecmult_odd_multiples_table_storage_var, which converts its
 *    resulting point set to actually affine points, and stores those in pre.
 *    It operates on tables of any size, but uses heap-allocated temporaries.
 *
 *  To compute a*P + b*G, we compute a table for P using the first function,
 *  and for G using the second (which requires an inverse, but it only needs to
 *  happen once).
 */
static void secp256k1_ecmult_odd_multiples_table_globalz_windowa(secp256k1_ge *pre, secp256k1_fe *globalz, const secp256k1_gej *a) {
    secp256k1_gej prej[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_fe zr[ECMULT_TABLE_SIZE(WINDOW_A)];

    /* Compute the odd multiples in Jacobian form. */
    secp256k1_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(WINDOW_A), prej, zr, a);
    /* Bring them to the same Z denominator. */
    secp256k1_ge_globalz_set_table_gej(ECMULT_TABLE_SIZE(WINDOW_A), pre, globalz, prej, zr);
}

static void secp256k1_ecmult_odd_multiples_table_storage_var(int n, secp256k1_ge_storage *pre, const secp256k1_gej *a, const secp256k1_callback *cb) {
    secp256k1_gej *prej = (secp256k1_gej*)checked_malloc(cb, sizeof(secp256k1_gej) * n);
    secp256k1_ge *prea = (secp256k1_ge*)checked_malloc(cb, sizeof(secp256k1_ge) * n);
    secp256k1_fe *zr = (secp256k1_fe*)checked_malloc(cb, sizeof(secp256k1_fe) * n);
    int i;

    /* Compute the odd multiples in Jacobian form. */
    secp256k1_ecmult_odd_multiples_table(n, prej, zr, a);
    /* Convert them in batch to affine coordinates. */
    secp256k1_ge_set_table_gej_var(n, prea, prej, zr);
    /* Convert them to compact storage form. */
    for (i = 0; i < n; i++) {
        secp256k1_ge_to_storage(&pre[i], &prea[i]);
    }

    free(prea);
    free(prej);
    free(zr);
}

/** The following two macro retrieves a particular odd multiple from a table
 *  of precomputed multiples. */
#define ECMULT_TABLE_GET_GE(r,pre,n,w) do { \
    VERIFY_CHECK(((n) & 1) == 1); \
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1)); \
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1)); \
    if ((n) > 0) { \
        *(r) = (pre)[((n)-1)/2]; \
    } else { \
        secp256k1_ge_neg((r), &(pre)[(-(n)-1)/2]); \
    } \
} while(0)

#define ECMULT_TABLE_GET_GE_STORAGE(r,pre,n,w) do { \
    VERIFY_CHECK(((n) & 1) == 1); \
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1)); \
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1)); \
    if ((n) > 0) { \
        secp256k1_ge_from_storage((r), &(pre)[((n)-1)/2]); \
    } else { \
        secp256k1_ge_from_storage((r), &(pre)[(-(n)-1)/2]); \
        secp256k1_ge_neg((r), (r)); \
    } \
} while(0)

static void secp256k1_ecmult_context_init(secp256k1_ecmult_context *ctx) {
    ctx->pre_g = NULL;
#ifdef USE_ENDOMORPHISM
    ctx->pre_g_128 = NULL;
#endif
}

static void secp256k1_ecmult_context_build(secp256k1_ecmult_context *ctx, const secp256k1_callback *cb) {
    secp256k1_gej gj;

    if (ctx->pre_g != NULL) {
        return;
    }

    /* get the generator */
    secp256k1_gej_set_ge(&gj, &secp256k1_ge_const_g);

    ctx->pre_g = (secp256k1_ge_storage (*)[])checked_malloc(cb, sizeof((*ctx->pre_g)[0]) * ECMULT_TABLE_SIZE(WINDOW_G));

    /* precompute the tables with odd multiples */
    secp256k1_ecmult_odd_multiples_table_storage_var(ECMULT_TABLE_SIZE(WINDOW_G), *ctx->pre_g, &gj, cb);

#ifdef USE_ENDOMORPHISM
    {
        secp256k1_gej g_128j;
        int i;

        ctx->pre_g_128 = (secp256k1_ge_storage (*)[])checked_malloc(cb, sizeof((*ctx->pre_g_128)[0]) * ECMULT_TABLE_SIZE(WINDOW_G));

        /* calculate 2^128*generator */
        g_128j = gj;
        for (i = 0; i < 128; i++) {
            secp256k1_gej_double_var(&g_128j, &g_128j, NULL);
        }
        secp256k1_ecmult_odd_multiples_table_storage_var(ECMULT_TABLE_SIZE(WINDOW_G), *ctx->pre_g_128, &g_128j, cb);
    }
#endif
}

static void secp256k1_ecmult_context_clone(secp256k1_ecmult_context *dst,
                                           const secp256k1_ecmult_context *src, const secp256k1_callback *cb) {
    if (src->pre_g == NULL) {
        dst->pre_g = NULL;
    } else {
        size_t size = sizeof((*dst->pre_g)[0]) * ECMULT_TABLE_SIZE(WINDOW_G);
        dst->pre_g = (secp256k1_ge_storage (*)[])checked_malloc(cb, size);
        memcpy(dst->pre_g, src->pre_g, size);
    }
#ifdef USE_ENDOMORPHISM
    if (src->pre_g_128 == NULL) {
        dst->pre_g_128 = NULL;
    } else {
        size_t size = sizeof((*dst->pre_g_128)[0]) * ECMULT_TABLE_SIZE(WINDOW_G);
        dst->pre_g_128 = (secp256k1_ge_storage (*)[])checked_malloc(cb, size);
        memcpy(dst->pre_g_128, src->pre_g_128, size);
    }
#endif
}


static void secp256k1_ecmult_context_clear(secp256k1_ecmult_context *ctx) {
    free(ctx->pre_g);
#ifdef USE_ENDOMORPHISM
    free(ctx->pre_g_128);
#endif
    secp256k1_ecmult_context_init(ctx);
}

/** Convert a number to WNAF notation. The number becomes represented by sum(2^i * wnaf[i], i=0..bits),
 *  with the following guarantees:
 *  - each wnaf[i] is either 0, or an odd integer between -(1<<(w-1) - 1) and (1<<(w-1) - 1)
 *  - two non-zero entries in wnaf are separated by at least w-1 zeroes.
 *  - the number of set values in wnaf is returned. This number is at most 256, and at most one more
 *    than the number of bits in the (absolute value) of the input.
 */
static int secp256k1_ecmult_wnaf(int *wnaf, int len, const secp256k1_scalar *a, int w) {
    secp256k1_scalar s = *a;
    int last_set_bit = -1;
    int bit = 0;
    int sign = 1;
    int carry = 0;

    //VERIFY_CHECK(wnaf != NULL);
    //VERIFY_CHECK(0 <= len && len <= 256);
    //VERIFY_CHECK(a != NULL);
    //VERIFY_CHECK(2 <= w && w <= 31);

    memset(wnaf, 0, len * sizeof(wnaf[0]));

    if (secp256k1_scalar_get_bits(&s, 255, 1)) {
        secp256k1_scalar_negate(&s, &s);
        sign = -1;
    }

    while (bit < len) {
        int now;
        int word;
        if (secp256k1_scalar_get_bits(&s, bit, 1) == (unsigned int)carry) {
            bit++;
            continue;
        }

        now = w;
        if (now > len - bit) {
            now = len - bit;
        }

        word = secp256k1_scalar_get_bits_var(&s, bit, now) + carry;

        carry = (word >> (w-1)) & 1;
        word -= carry << w;

        wnaf[bit] = sign * word;
        last_set_bit = bit;

        bit += now;
    }
#ifdef VERIFY
    CHECK(carry == 0);
    while (bit < 256) {
        CHECK(secp256k1_scalar_get_bits(&s, bit++, 1) == 0);
    }
#endif
    return last_set_bit + 1;
}

static void secp256k1_ecmult(const secp256k1_ecmult_context *ctx, secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) {
    secp256k1_ge pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_ge tmpa;
    secp256k1_fe Z;
#ifdef USE_ENDOMORPHISM
    secp256k1_ge pre_a_lam[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_scalar na_1, na_lam;
    /* Splitted G factors. */
    secp256k1_scalar ng_1, ng_128;
    int wnaf_na_1[130];
    int wnaf_na_lam[130];
    int bits_na_1;
    int bits_na_lam;
    int wnaf_ng_1[129];
    int bits_ng_1;
    int wnaf_ng_128[129];
    int bits_ng_128;
#else
    int wnaf_na[256];
    int bits_na;
    int wnaf_ng[256];
    int bits_ng;
#endif
    int i;
    int bits;

#ifdef USE_ENDOMORPHISM
    /* split na into na_1 and na_lam (where na = na_1 + na_lam*lambda, and na_1 and na_lam are ~128 bit) */
    secp256k1_scalar_split_lambda(&na_1, &na_lam, na);

    /* build wnaf representation for na_1 and na_lam. */
    bits_na_1   = secp256k1_ecmult_wnaf(wnaf_na_1,   130, &na_1,   WINDOW_A);
    bits_na_lam = secp256k1_ecmult_wnaf(wnaf_na_lam, 130, &na_lam, WINDOW_A);
    VERIFY_CHECK(bits_na_1 <= 130);
    VERIFY_CHECK(bits_na_lam <= 130);
    bits = bits_na_1;
    if (bits_na_lam > bits) {
        bits = bits_na_lam;
    }
#else
    /* build wnaf representation for na. */
    bits_na     = secp256k1_ecmult_wnaf(wnaf_na,     256, na,      WINDOW_A);
    bits = bits_na;
#endif

    /* Calculate odd multiples of a.
     * All multiples are brought to the same Z 'denominator', which is stored
     * in Z. Due to secp256k1' isomorphism we can do all operations pretending
     * that the Z coordinate was 1, use affine addition formulae, and correct
     * the Z coordinate of the result once at the end.
     * The exception is the precomputed G table points, which are actually
     * affine. Compared to the base used for other points, they have a Z ratio
     * of 1/Z, so we can use secp256k1_gej_add_zinv_var, which uses the same
     * isomorphism to efficiently add with a known Z inverse.
     */
    secp256k1_ecmult_odd_multiples_table_globalz_windowa(pre_a, &Z, a);

#ifdef USE_ENDOMORPHISM
    for (i = 0; i < ECMULT_TABLE_SIZE(WINDOW_A); i++) {
        secp256k1_ge_mul_lambda(&pre_a_lam[i], &pre_a[i]);
    }

    /* split ng into ng_1 and ng_128 (where gn = gn_1 + gn_128*2^128, and gn_1 and gn_128 are ~128 bit) */
    secp256k1_scalar_split_128(&ng_1, &ng_128, ng);

    /* Build wnaf representation for ng_1 and ng_128 */
    bits_ng_1   = secp256k1_ecmult_wnaf(wnaf_ng_1,   129, &ng_1,   WINDOW_G);
    bits_ng_128 = secp256k1_ecmult_wnaf(wnaf_ng_128, 129, &ng_128, WINDOW_G);
    if (bits_ng_1 > bits) {
        bits = bits_ng_1;
    }
    if (bits_ng_128 > bits) {
        bits = bits_ng_128;
    }
#else
    bits_ng     = secp256k1_ecmult_wnaf(wnaf_ng,     256, ng,      WINDOW_G);
    if (bits_ng > bits) {
        bits = bits_ng;
    }
#endif

    secp256k1_gej_set_infinity(r);

    for (i = bits - 1; i >= 0; i--) {
        int n;
        secp256k1_gej_double_var(r, r, NULL);
#ifdef USE_ENDOMORPHISM
        if (i < bits_na_1 && (n = wnaf_na_1[i])) {
            ECMULT_TABLE_GET_GE(&tmpa, pre_a, n, WINDOW_A);
            secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
        }
        if (i < bits_na_lam && (n = wnaf_na_lam[i])) {
            ECMULT_TABLE_GET_GE(&tmpa, pre_a_lam, n, WINDOW_A);
            secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
        }
        if (i < bits_ng_1 && (n = wnaf_ng_1[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx->pre_g, n, WINDOW_G);
            secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
        if (i < bits_ng_128 && (n = wnaf_ng_128[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx->pre_g_128, n, WINDOW_G);
            secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
#else
        if (i < bits_na && (n = wnaf_na[i])) {
            ECMULT_TABLE_GET_GE(&tmpa, pre_a, n, WINDOW_A);
            secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
        }
        if (i < bits_ng && (n = wnaf_ng[i])) {
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx->pre_g, n, WINDOW_G);
            secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
#endif
    }

    if (!r->infinity) {
        secp256k1_fe_mul(&r->z, &r->z, &Z);
    }
}



static void secp256k1_ge_set_xy(secp256k1_ge *r, const secp256k1_fe *x, const secp256k1_fe *y) {
    r->infinity = 0;
    r->x = *x;
    r->y = *y;
}

static int secp256k1_ge_is_infinity(const secp256k1_ge *a) {
    return a->infinity;
}

static void secp256k1_ge_neg(secp256k1_ge *r, const secp256k1_ge *a) {
    *r = *a;
    secp256k1_fe_normalize_weak(&r->y);
    secp256k1_fe_negate(&r->y, &r->y, 1);
}

static void secp256k1_ge_set_gej(secp256k1_ge *r, secp256k1_gej *a) {
    secp256k1_fe z2, z3;
    r->infinity = a->infinity;
    secp256k1_fe_inv(&a->z, &a->z);
    secp256k1_fe_sqr(&z2, &a->z);
    secp256k1_fe_mul(&z3, &a->z, &z2);
    secp256k1_fe_mul(&a->x, &a->x, &z2);
    secp256k1_fe_mul(&a->y, &a->y, &z3);
    secp256k1_fe_set_int(&a->z, 1);
    r->x = a->x;
    r->y = a->y;
}



static void secp256k1_ge_set_table_gej_var(size_t len, secp256k1_ge *r, const secp256k1_gej *a, const secp256k1_fe *zr) {
    size_t i = len - 1;
    secp256k1_fe zi;

    if (len > 0) {
        /* Compute the inverse of the last z coordinate, and use it to compute the last affine output. */
        secp256k1_fe_inv(&zi, &a[i].z);
        secp256k1_ge_set_gej_zinv(&r[i], &a[i], &zi);

        /* Work out way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            secp256k1_fe_mul(&zi, &zi, &zr[i]);
            i--;
            secp256k1_ge_set_gej_zinv(&r[i], &a[i], &zi);
        }
    }
}

static void secp256k1_ge_globalz_set_table_gej(size_t len, secp256k1_ge *r, secp256k1_fe *globalz, const secp256k1_gej *a, const secp256k1_fe *zr) {
    size_t i = len - 1;
    secp256k1_fe zs;

    if (len > 0) {
        /* The z of the final point gives us the "global Z" for the table. */
        r[i].x = a[i].x;
        r[i].y = a[i].y;
        *globalz = a[i].z;
        r[i].infinity = 0;
        zs = zr[i];

        /* Work our way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            if (i != len - 1) {
                secp256k1_fe_mul(&zs, &zs, &zr[i]);
            }
            i--;
            secp256k1_ge_set_gej_zinv(&r[i], &a[i], &zs);
        }
    }
}

static void secp256k1_gej_set_infinity(secp256k1_gej *r) {
    r->infinity = 1;
    secp256k1_fe_set_int(&r->x, 0);
    secp256k1_fe_set_int(&r->y, 0);
    secp256k1_fe_set_int(&r->z, 0);
}

static void secp256k1_gej_clear(secp256k1_gej *r) {
    r->infinity = 0;
    secp256k1_fe_clear(&r->x);
    secp256k1_fe_clear(&r->y);
    secp256k1_fe_clear(&r->z);
}

static void secp256k1_ge_clear(secp256k1_ge *r) {
    r->infinity = 0;
    secp256k1_fe_clear(&r->x);
    secp256k1_fe_clear(&r->y);
}

static int secp256k1_ge_set_xquad_var(secp256k1_ge *r, const secp256k1_fe *x) {
    secp256k1_fe x2, x3, c;
    r->x = *x;
    secp256k1_fe_sqr(&x2, x);
    secp256k1_fe_mul(&x3, x, &x2);
    r->infinity = 0;
    secp256k1_fe_set_int(&c, 7);
    secp256k1_fe_add(&c, &x3);
    return secp256k1_fe_sqrt_var(&r->y, &c);
}

static int secp256k1_ge_set_xo_var(secp256k1_ge *r, const secp256k1_fe *x, int odd) {
    if (!secp256k1_ge_set_xquad_var(r, x)) {
        return 0;
    }
    secp256k1_fe_normalize_var(&r->y);
    if (secp256k1_fe_is_odd(&r->y) != odd) {
        secp256k1_fe_negate(&r->y, &r->y, 1);
    }
    return 1;

}

static void secp256k1_gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a) {
   r->infinity = a->infinity;
   r->x = a->x;
   r->y = a->y;
   secp256k1_fe_set_int(&r->z, 1);
}

static void secp256k1_gej_neg(secp256k1_gej *r, const secp256k1_gej *a) {
    r->infinity = a->infinity;
    r->x = a->x;
    r->y = a->y;
    r->z = a->z;
    secp256k1_fe_normalize_weak(&r->y);
    secp256k1_fe_negate(&r->y, &r->y, 1);
}

static int secp256k1_gej_is_infinity(const secp256k1_gej *a) {
    return a->infinity;
}

static int secp256k1_ge_is_valid_var(const secp256k1_ge *a) {
    secp256k1_fe y2, x3, c;
    if (a->infinity) {
        return 0;
    }
    /* y^2 = x^3 + 7 */
    secp256k1_fe_sqr(&y2, &a->y);
    secp256k1_fe_sqr(&x3, &a->x); secp256k1_fe_mul(&x3, &x3, &a->x);
    secp256k1_fe_set_int(&c, 7);
    secp256k1_fe_add(&x3, &c);
    secp256k1_fe_normalize_weak(&x3);
    return secp256k1_fe_equal_var(&y2, &x3);
}

static void secp256k1_gej_double_var(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr) {
    /* Operations: 3 mul, 4 sqr, 0 normalize, 12 mul_int/add/negate */
    secp256k1_fe t1,t2,t3,t4;
    /** For secp256k1, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
     *  Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a point on y^2 = x^3 + 7 to have
     *  y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
     *
     *  Having said this, if this function receives a point on a sextic twist, e.g. by
     *  a fault attack, it is possible for y to be 0. This happens for y^2 = x^3 + 6,
     *  since -6 does have a cube root mod p. For this point, this function will not set
     *  the infinity flag even though the point doubles to infinity, and the result
     *  point will be gibberish (z = 0 but infinity = 0).
     */
    r->infinity = a->infinity;
    if (r->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        }
        return;
    }

    if (rzr != NULL) {
        *rzr = a->y;
        secp256k1_fe_normalize_weak(rzr);
        secp256k1_fe_mul_int(rzr, 2);
    }

    secp256k1_fe_mul(&r->z, &a->z, &a->y);
    secp256k1_fe_mul_int(&r->z, 2);       /* Z' = 2*Y*Z (2) */
    secp256k1_fe_sqr(&t1, &a->x);
    secp256k1_fe_mul_int(&t1, 3);         /* T1 = 3*X^2 (3) */
    secp256k1_fe_sqr(&t2, &t1);           /* T2 = 9*X^4 (1) */
    secp256k1_fe_sqr(&t3, &a->y);
    secp256k1_fe_mul_int(&t3, 2);         /* T3 = 2*Y^2 (2) */
    secp256k1_fe_sqr(&t4, &t3);
    secp256k1_fe_mul_int(&t4, 2);         /* T4 = 8*Y^4 (2) */
    secp256k1_fe_mul(&t3, &t3, &a->x);    /* T3 = 2*X*Y^2 (1) */
    r->x = t3;
    secp256k1_fe_mul_int(&r->x, 4);       /* X' = 8*X*Y^2 (4) */
    secp256k1_fe_negate(&r->x, &r->x, 4); /* X' = -8*X*Y^2 (5) */
    secp256k1_fe_add(&r->x, &t2);         /* X' = 9*X^4 - 8*X*Y^2 (6) */
    secp256k1_fe_negate(&t2, &t2, 1);     /* T2 = -9*X^4 (2) */
    secp256k1_fe_mul_int(&t3, 6);         /* T3 = 12*X*Y^2 (6) */
    secp256k1_fe_add(&t3, &t2);           /* T3 = 12*X*Y^2 - 9*X^4 (8) */
    secp256k1_fe_mul(&r->y, &t1, &t3);    /* Y' = 36*X^3*Y^2 - 27*X^6 (1) */
    secp256k1_fe_negate(&t2, &t4, 2);     /* T2 = -8*Y^4 (3) */
    secp256k1_fe_add(&r->y, &t2);         /* Y' = 36*X^3*Y^2 - 27*X^6 - 8*Y^4 (4) */
}


static void secp256k1_gej_add_ge_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, secp256k1_fe *rzr) {
    /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    secp256k1_fe z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;
    if (a->infinity) {
        //VERIFY_CHECK(rzr == NULL);
        secp256k1_gej_set_ge(r, b);
        return;
    }
    if (b->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        }
        *r = *a;
        return;
    }
    r->infinity = 0;

    secp256k1_fe_sqr(&z12, &a->z);
    u1 = a->x; secp256k1_fe_normalize_weak(&u1);
    secp256k1_fe_mul(&u2, &b->x, &z12);
    s1 = a->y; secp256k1_fe_normalize_weak(&s1);
    secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
    secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var(r, a, rzr);
        } else {
            if (rzr != NULL) {
                secp256k1_fe_set_int(rzr, 0);
            }
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_sqr(&i2, &i);
    secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_mul(&h3, &h, &h2);
    if (rzr != NULL) {
        *rzr = h;
    }
    secp256k1_fe_mul(&r->z, &a->z, &h);
    secp256k1_fe_mul(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3); secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
    secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t); secp256k1_fe_mul(&r->y, &r->y, &i);
    secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
    secp256k1_fe_add(&r->y, &h3);
}

static void secp256k1_gej_add_zinv_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, const secp256k1_fe *bzinv) {
    /* 9 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    secp256k1_fe az, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

    if (b->infinity) {
        *r = *a;
        return;
    }
    if (a->infinity) {
        secp256k1_fe bzinv2, bzinv3;
        r->infinity = b->infinity;
        secp256k1_fe_sqr(&bzinv2, bzinv);
        secp256k1_fe_mul(&bzinv3, &bzinv2, bzinv);
        secp256k1_fe_mul(&r->x, &b->x, &bzinv2);
        secp256k1_fe_mul(&r->y, &b->y, &bzinv3);
        secp256k1_fe_set_int(&r->z, 1);
        return;
    }
    r->infinity = 0;

    /** We need to calculate (rx,ry,rz) = (ax,ay,az) + (bx,by,1/bzinv). Due to
     *  secp256k1's isomorphism we can multiply the Z coordinates on both sides
     *  by bzinv, and get: (rx,ry,rz*bzinv) = (ax,ay,az*bzinv) + (bx,by,1).
     *  This means that (rx,ry,rz) can be calculated as
     *  (ax,ay,az*bzinv) + (bx,by,1), when not applying the bzinv factor to rz.
     *  The variable az below holds the modified Z coordinate for a, which is used
     *  for the computation of rx and ry, but not for rz.
     */
    secp256k1_fe_mul(&az, &a->z, bzinv);

    secp256k1_fe_sqr(&z12, &az);
    u1 = a->x; secp256k1_fe_normalize_weak(&u1);
    secp256k1_fe_mul(&u2, &b->x, &z12);
    s1 = a->y; secp256k1_fe_normalize_weak(&s1);
    secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &az);
    secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var(r, a, NULL);
        } else {
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_sqr(&i2, &i);
    secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_mul(&h3, &h, &h2);
    r->z = a->z; secp256k1_fe_mul(&r->z, &r->z, &h);
    secp256k1_fe_mul(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3); secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
    secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t); secp256k1_fe_mul(&r->y, &r->y, &i);
    secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
    secp256k1_fe_add(&r->y, &h3);
}


static void secp256k1_gej_rescale(secp256k1_gej *r, const secp256k1_fe *s) {
    /* Operations: 4 mul, 1 sqr */
    secp256k1_fe zz;
    //VERIFY_CHECK(!secp256k1_fe_is_zero(s));
    secp256k1_fe_sqr(&zz, s);
    secp256k1_fe_mul(&r->x, &r->x, &zz);                /* r->x *= s^2 */
    secp256k1_fe_mul(&r->y, &r->y, &zz);
    secp256k1_fe_mul(&r->y, &r->y, s);                  /* r->y *= s^3 */
    secp256k1_fe_mul(&r->z, &r->z, s);                  /* r->z *= s   */
}

static void secp256k1_ge_to_storage(secp256k1_ge_storage *r, const secp256k1_ge *a) {
    secp256k1_fe x, y;
    //VERIFY_CHECK(!a->infinity);
    x = a->x;
    secp256k1_fe_normalize(&x);
    y = a->y;
    secp256k1_fe_normalize(&y);
    secp256k1_fe_to_storage(&r->x, &x);
    secp256k1_fe_to_storage(&r->y, &y);
}

static void secp256k1_ge_from_storage(secp256k1_ge *r, const secp256k1_ge_storage *a) {
    secp256k1_fe_from_storage(&r->x, &a->x);
    secp256k1_fe_from_storage(&r->y, &a->y);
    r->infinity = 0;
}

#ifdef USE_ENDOMORPHISM
static void secp256k1_ge_mul_lambda(secp256k1_ge *r, const secp256k1_ge *a) {
    static const secp256k1_fe beta = SECP256K1_FE_CONST(
        0x7ae96a2bul, 0x657c0710ul, 0x6e64479eul, 0xac3434e9ul,
        0x9cf04975ul, 0x12f58995ul, 0xc1396c28ul, 0x719501eeul
    );
    *r = *a;
    secp256k1_fe_mul(&r->x, &r->x, &beta);
}
#endif

/* Force callers to use variable runtime versions */
#define secp256k1_gej_add_ge(r, a, b) secp256k1_gej_add_ge_var(r, a, b, NULL)





#ifdef USE_ENDOMORPHISM
/**
 * The Secp256k1 curve has an endomorphism, where lambda * (x, y) = (beta * x, y), where
 * lambda is {0x53,0x63,0xad,0x4c,0xc0,0x5c,0x30,0xe0,0xa5,0x26,0x1c,0x02,0x88,0x12,0x64,0x5a,
 *            0x12,0x2e,0x22,0xea,0x20,0x81,0x66,0x78,0xdf,0x02,0x96,0x7c,0x1b,0x23,0xbd,0x72}
 *
 * "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone) gives an algorithm
 * (algorithm 3.74) to find k1 and k2 given k, such that k1 + k2 * lambda == k mod n, and k1
 * and k2 have a small size.
 * It relies on constants a1, b1, a2, b2. These constants for the value of lambda above are:
 *
 * - a1 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
 * - b1 =     -{0xe4,0x43,0x7e,0xd6,0x01,0x0e,0x88,0x28,0x6f,0x54,0x7f,0xa9,0x0a,0xbf,0xe4,0xc3}
 * - a2 = {0x01,0x14,0xca,0x50,0xf7,0xa8,0xe2,0xf3,0xf6,0x57,0xc1,0x10,0x8d,0x9d,0x44,0xcf,0xd8}
 * - b2 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
 *
 * The algorithm then computes c1 = round(b1 * k / n) and c2 = round(b2 * k / n), and gives
 * k1 = k - (c1*a1 + c2*a2) and k2 = -(c1*b1 + c2*b2). Instead, we use modular arithmetic, and
 * compute k1 as k - k2 * lambda, avoiding the need for constants a1 and a2.
 *
 * g1, g2 are precomputed constants used to replace division with a rounded multiplication
 * when decomposing the scalar for an endomorphism-based point multiplication.
 *
 * The possibility of using precomputed estimates is mentioned in "Guide to Elliptic Curve
 * Cryptography" (Hankerson, Menezes, Vanstone) in section 3.5.
 *
 * The derivation is described in the paper "Efficient Software Implementation of Public-Key
 * Cryptography on Sensor Networks Using the MSP430X Microcontroller" (Gouvea, Oliveira, Lopez),
 * Section 4.3 (here we use a somewhat higher-precision estimate):
 * d = a1*b2 - b1*a2
 * g1 = round((2^272)*b2/d)
 * g2 = round((2^272)*b1/d)
 *
 * (Note that 'd' is also equal to the curve order here because [a1,b1] and [a2,b2] are found
 * as outputs of the Extended Euclidean Algorithm on inputs 'order' and 'lambda').
 *
 * The function below splits a in r1 and r2, such that r1 + lambda * r2 == a (mod order).
 */

static void secp256k1_scalar_split_lambda(secp256k1_scalar *r1, secp256k1_scalar *r2, const secp256k1_scalar *a) {
    secp256k1_scalar c1, c2;
    static const secp256k1_scalar minus_lambda = SECP256K1_SCALAR_CONST(
        0xAC9C52B3UL, 0x3FA3CF1FUL, 0x5AD9E3FDUL, 0x77ED9BA4UL,
        0xA880B9FCUL, 0x8EC739C2UL, 0xE0CFC810UL, 0xB51283CFUL
    );
    static const secp256k1_scalar minus_b1 = SECP256K1_SCALAR_CONST(
        0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
        0xE4437ED6UL, 0x010E8828UL, 0x6F547FA9UL, 0x0ABFE4C3UL
    );
    static const secp256k1_scalar minus_b2 = SECP256K1_SCALAR_CONST(
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL,
        0x8A280AC5UL, 0x0774346DUL, 0xD765CDA8UL, 0x3DB1562CUL
    );
    static const secp256k1_scalar g1 = SECP256K1_SCALAR_CONST(
        0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00003086UL,
        0xD221A7D4UL, 0x6BCDE86CUL, 0x90E49284UL, 0xEB153DABUL
    );
    static const secp256k1_scalar g2 = SECP256K1_SCALAR_CONST(
        0x00000000UL, 0x00000000UL, 0x00000000UL, 0x0000E443UL,
        0x7ED6010EUL, 0x88286F54UL, 0x7FA90ABFUL, 0xE4C42212UL
    );
    VERIFY_CHECK(r1 != a);
    VERIFY_CHECK(r2 != a);
    /* these _var calls are constant time since the shift amount is constant */
    secp256k1_scalar_mul_shift_var(&c1, a, &g1, 272);
    secp256k1_scalar_mul_shift_var(&c2, a, &g2, 272);
    secp256k1_scalar_mul(&c1, &c1, &minus_b1);
    secp256k1_scalar_mul(&c2, &c2, &minus_b2);
    secp256k1_scalar_add(r2, &c1, &c2);
    secp256k1_scalar_mul(r1, r2, &minus_lambda);
    secp256k1_scalar_add(r1, r1, a);
}
#endif



/* Force callers to use variable runtime versions */
#define secp256k1_scalar_inverse(r, x) secp256k1_scalar_inverse_var(r, x)

SECP256K1_INLINE static int secp256k1_fe_equal_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe na;
    secp256k1_fe_negate(&na, a, 1);
    secp256k1_fe_add(&na, b);
    return secp256k1_fe_normalizes_to_zero_var(&na);
}

static int secp256k1_fe_sqrt_var(secp256k1_fe *r, const secp256k1_fe *a) {
    /** Given that p is congruent to 3 mod 4, we can compute the square root of
     *  a mod p as the (p+1)/4'th power of a.
     *
     *  As (p+1)/4 is an even number, it will have the same result for a and for
     *  (-a). Only one of these two numbers actually has a square root however,
     *  so we test at the end by squaring and comparing to the input.
     *  Also because (p+1)/4 is an even number, the computed square root is
     *  itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
     */
    secp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    /** The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
     *  { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    secp256k1_fe_sqr(&x2, a);
    secp256k1_fe_mul(&x2, &x2, a);

    secp256k1_fe_sqr(&x3, &x2);
    secp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x6, &x6);
    }
    secp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x9, &x9);
    }
    secp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        secp256k1_fe_sqr(&x11, &x11);
    }
    secp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        secp256k1_fe_sqr(&x22, &x22);
    }
    secp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        secp256k1_fe_sqr(&x44, &x44);
    }
    secp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x88, &x88);
    }
    secp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        secp256k1_fe_sqr(&x176, &x176);
    }
    secp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x220, &x220);
    }
    secp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x223, &x223);
    }
    secp256k1_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x22);
    for (j=0; j<6; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x2);
    secp256k1_fe_sqr(&t1, &t1);
    secp256k1_fe_sqr(r, &t1);

    /* Check that a square root was actually calculated */

    secp256k1_fe_sqr(&t1, r);
    return secp256k1_fe_equal_var(&t1, a);
}

static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    /** The binary representation of (p - 2) has 5 blocks of 1s, with lengths in
     *  { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    secp256k1_fe_sqr(&x2, a);
    secp256k1_fe_mul(&x2, &x2, a);

    secp256k1_fe_sqr(&x3, &x2);
    secp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x6, &x6);
    }
    secp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x9, &x9);
    }
    secp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        secp256k1_fe_sqr(&x11, &x11);
    }
    secp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        secp256k1_fe_sqr(&x22, &x22);
    }
    secp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        secp256k1_fe_sqr(&x44, &x44);
    }
    secp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x88, &x88);
    }
    secp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        secp256k1_fe_sqr(&x176, &x176);
    }
    secp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x220, &x220);
    }
    secp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x223, &x223);
    }
    secp256k1_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x22);
    for (j=0; j<5; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, a);
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x2);
    for (j=0; j<2; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(r, a, &t1);
}

static void secp256k1_fe_inv_var(secp256k1_fe *r, const secp256k1_fe *a) {
#if defined(USE_FIELD_INV_BUILTIN)
    secp256k1_fe_inv(r, a);
#elif defined(USE_FIELD_INV_NUM)
    secp256k1_num n, m;
    static const secp256k1_fe negone = SECP256K1_FE_CONST(
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0xFFFFFC2EUL
    );
    /* secp256k1 field prime, value p defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    static const unsigned char prime[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
    };
    unsigned char b[32];
    int res;
    secp256k1_fe c = *a;
    secp256k1_fe_normalize_var(&c);

    /*
        Never call secp256k1_num_mod_inverse() with a = 0.
        The constant time secp256k1_fe_inv doesn't care and doesn't check.
        Now that we force everybody to use this variable runtime version, we need
        to make sure that a != 0 because secp256k1_num_mod_inverse will check that GCD(a, m) == 1
    */
    if ( secp256k1_fe_is_zero(&c) ) {
        /* Garbage in, garbage out */
        *r = *a;
        return;
    }

    secp256k1_fe_get_b32(b, &c);
    secp256k1_num_set_bin(&n, b, 32);
    secp256k1_num_set_bin(&m, prime, 32);
    secp256k1_num_mod_inverse(&n, &n, &m);
    secp256k1_num_get_bin(b, 32, &n);
    res = secp256k1_fe_set_b32(r, b);
    (void)res;
#ifdef VERIFY
    /* Verify the result is the (unique) valid inverse using non-GMP code. */
    VERIFY_CHECK(res);
    secp256k1_fe_mul(&c, &c, r);
    secp256k1_fe_add(&c, &negone);
    CHECK(secp256k1_fe_normalizes_to_zero_var(&c));
#else
    (void)negone;
#endif
#else
#error "Please select field inverse implementation"
#endif
}

static void secp256k1_fe_inv_all_var(size_t len, secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe u;
    size_t i;
    if (len < 1) {
        return;
    }

    //VERIFY_CHECK((r + len <= a) || (a + len <= r));

    r[0] = a[0];

    /* a = {a,  b,   c} */
    /* r = {a, ab, abc} */
    i = 0;
    while (++i < len) {
        secp256k1_fe_mul(&r[i], &r[i - 1], &a[i]);
    }

    /* u = (abc)^1 */
    secp256k1_fe_inv_var(&u, &r[--i]);

    while (i > 0) {
        /* j = current, i = previous    */
        size_t j = i--;

        /* r[cur] = r[prev] * u         */
        /* r[cur] = (ab)    * (abc)^-1  */
        /* r[cur] = c^-1                */
        /* r = {a, ab, c^-1}            */
        secp256k1_fe_mul(&r[j], &r[i], &u);

        /* u = (abc)^-1 * c = (ab)^-1   */
        secp256k1_fe_mul(&u, &u, &a[j]);
    }

    /* Last iteration handled separately, at this point u = a^-1 */
    r[0] = u;
}

/* Force callers to use variable runtime versions */
#define secp256k1_fe_inv(r, a) secp256k1_fe_inv_var(r, a)



static void secp256k1_num_get_bin(unsigned char *r, unsigned int rlen, const secp256k1_num *a) {
    unsigned char tmp[65];
    int len = 0;
    int shift = 0;
    if (a->limbs>1 || a->data[0] != 0) {
        len = mpn_get_str(tmp, 256, (mp_limb_t*)a->data, a->limbs);
    }
    while (shift < len && tmp[shift] == 0) shift++;
    //VERIFY_CHECK(len-shift <= (int)rlen);
    memset(r, 0, rlen - len + shift);
    if (len > shift) {
        memcpy(r + rlen - len + shift, tmp + shift, len - shift);
    }
    /* memset(tmp, 0, sizeof(tmp)); */
}

static void secp256k1_num_set_bin(secp256k1_num *r, const unsigned char *a, unsigned int alen) {
    int len;
    //VERIFY_CHECK(alen > 0);
    //VERIFY_CHECK(alen <= 64);
    len = mpn_set_str(r->data, a, alen, 256);
    if (len == 0) {
        r->data[0] = 0;
        len = 1;
    }
    //VERIFY_CHECK(len <= NUM_LIMBS*2);
    r->limbs = len;
    r->neg = 0;
    while (r->limbs > 1 && r->data[r->limbs-1]==0) {
        r->limbs--;
    }
}



static void secp256k1_num_mod_inverse(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *m) {
    int i;
    mp_limb_t g[NUM_LIMBS+1];
    mp_limb_t u[NUM_LIMBS+1];
    mp_limb_t v[NUM_LIMBS+1];
    mp_size_t sn;
    mp_size_t gn;
    secp256k1_num_sanity(a);
    secp256k1_num_sanity(m);

    /** mpn_gcdext computes: (G,S) = gcdext(U,V), where
     *  * G = gcd(U,V)
     *  * G = U*S + V*T
     *  * U has equal or more limbs than V, and V has no padding
     *  If we set U to be (a padded version of) a, and V = m:
     *    G = a*S + m*T
     *    G = a*S mod m
     *  Assuming G=1:
     *    S = 1/a mod m
     */
    //VERIFY_CHECK(m->limbs <= NUM_LIMBS);
    //VERIFY_CHECK(m->data[m->limbs-1] != 0);
    for (i = 0; i < m->limbs; i++) {
        u[i] = (i < a->limbs) ? a->data[i] : 0;
        v[i] = m->data[i];
    }
    sn = NUM_LIMBS+1;
    gn = mpn_gcdext(g, r->data, &sn, u, m->limbs, v, m->limbs);
    (void)gn;
    //VERIFY_CHECK(gn == 1);
    //VERIFY_CHECK(g[0] == 1);
    r->neg = a->neg ^ m->neg;
    if (sn < 0) {
        mpn_sub(r->data, m->data, m->limbs, r->data, -sn);
        r->limbs = m->limbs;
        while (r->limbs > 1 && r->data[r->limbs-1]==0) {
            r->limbs--;
        }
    } else {
        r->limbs = sn;
    }

    /* memset(g, 0, sizeof(g)); */
    /* memset(u, 0, sizeof(u)); */
    /* memset(v, 0, sizeof(v)); */
}



static void default_illegal_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] illegal argument: %s\n", str);
    abort();
}


static void default_error_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] internal consistency check failed: %s\n", str);
    abort();
}


secp256k1_context* secp256k1_context_create(unsigned int flags) {
    secp256k1_context* ret = (secp256k1_context*)checked_malloc(&default_error_callback, sizeof(secp256k1_context));
    ret->illegal_callback = default_illegal_callback;
    ret->error_callback = default_error_callback;

    if (EXPECT((flags & SECP256K1_FLAGS_TYPE_MASK) != SECP256K1_FLAGS_TYPE_CONTEXT, 0)) {
            secp256k1_callback_call(&ret->illegal_callback,
                                    "Invalid flags");
            free(ret);
            return NULL;
    }

    secp256k1_ecmult_context_init(&ret->ecmult_ctx);
    secp256k1_ecmult_gen_context_init(&ret->ecmult_gen_ctx);

    if (flags & SECP256K1_FLAGS_BIT_CONTEXT_SIGN) {
        secp256k1_ecmult_gen_context_build(&ret->ecmult_gen_ctx, &ret->error_callback);
    }
    if (flags & SECP256K1_FLAGS_BIT_CONTEXT_VERIFY) {
        secp256k1_ecmult_context_build(&ret->ecmult_ctx, &ret->error_callback);
    }

    return ret;
}

secp256k1_context* secp256k1_context_clone(const secp256k1_context* ctx) {
    secp256k1_context* ret = (secp256k1_context*)checked_malloc(&ctx->error_callback, sizeof(secp256k1_context));
    ret->illegal_callback = ctx->illegal_callback;
    ret->error_callback = ctx->error_callback;
    secp256k1_ecmult_context_clone(&ret->ecmult_ctx, &ctx->ecmult_ctx, &ctx->error_callback);
    secp256k1_ecmult_gen_context_clone(&ret->ecmult_gen_ctx, &ctx->ecmult_gen_ctx, &ctx->error_callback);
    return ret;
}

void secp256k1_context_destroy(secp256k1_context* ctx) {
    if (ctx != NULL) {
        secp256k1_ecmult_context_clear(&ctx->ecmult_ctx);
        secp256k1_ecmult_gen_context_clear(&ctx->ecmult_gen_ctx);

        free(ctx);
    }
}

void secp256k1_context_set_illegal_callback(secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    if (fun == NULL) {
        fun = default_illegal_callback_fn;
    }
    ctx->illegal_callback.fn = fun;
    ctx->illegal_callback.data = data;
}

void secp256k1_context_set_error_callback(secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    if (fun == NULL) {
        fun = default_error_callback_fn;
    }
    ctx->error_callback.fn = fun;
    ctx->error_callback.data = data;
}

static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        /* When the secp256k1_ge_storage type is exactly 64 byte, use its
         * representation inside secp256k1_pubkey, as conversion is very fast.
         * Note that secp256k1_pubkey_save must use the same representation. */
        secp256k1_ge_storage s;
        memcpy(&s, &pubkey->data[0], 64);
        secp256k1_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        secp256k1_fe x, y;
        secp256k1_fe_set_b32(&x, pubkey->data);
        secp256k1_fe_set_b32(&y, pubkey->data + 32);
        secp256k1_ge_set_xy(ge, &x, &y);
    }
    //ARG_CHECK(!secp256k1_fe_is_zero(&ge->x));
    return 1;
}

static void secp256k1_pubkey_save(secp256k1_pubkey* pubkey, secp256k1_ge* ge) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        secp256k1_ge_storage s;
        secp256k1_ge_to_storage(&s, ge);
        memcpy(&pubkey->data[0], &s, 64);
    } else {
        //VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
        secp256k1_fe_normalize_var(&ge->x);
        secp256k1_fe_normalize_var(&ge->y);
        secp256k1_fe_get_b32(pubkey->data, &ge->x);
        secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
    }
}

int secp256k1_ec_pubkey_parse(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen) {
    secp256k1_ge Q;

    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    //ARG_CHECK(input != NULL);
    if (!secp256k1_eckey_pubkey_parse(&Q, input, inputlen)) {
        return 0;
    }
    secp256k1_pubkey_save(pubkey, &Q);
    secp256k1_ge_clear(&Q);
    return 1;
}





int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey) {
    secp256k1_scalar sec;
    int ret;
    int overflow;
    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(seckey != NULL);

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = !overflow && !secp256k1_scalar_is_zero(&sec);
    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey) {
    secp256k1_gej pj;
    secp256k1_ge p;
    secp256k1_scalar sec;
    int overflow;
    int ret = 0;
    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    //ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    //ARG_CHECK(seckey != NULL);

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = (!overflow) & (!secp256k1_scalar_is_zero(&sec));
    if (ret) {
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pj, &sec);
        secp256k1_ge_set_gej(&p, &pj);
        secp256k1_pubkey_save(pubkey, &p);
    }
    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_ec_privkey_tweak_add(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    secp256k1_scalar term;
    secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(seckey != NULL);
    //ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&term, tweak, &overflow);
    secp256k1_scalar_set_b32(&sec, seckey, NULL);

    ret = !overflow && secp256k1_eckey_privkey_tweak_add(&sec, &term);
    memset(seckey, 0, 32);
    if (ret) {
        secp256k1_scalar_get_b32(seckey, &sec);
    }

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&term);
    return ret;
}

int secp256k1_ec_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    secp256k1_ge p;
    secp256k1_scalar term;
    int ret = 0;
    int overflow = 0;
    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    //ARG_CHECK(pubkey != NULL);
    //ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&term, tweak, &overflow);
    ret = !overflow && secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (secp256k1_eckey_pubkey_tweak_add(&ctx->ecmult_ctx, &p, &term)) {
            secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int secp256k1_ec_privkey_tweak_mul(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    secp256k1_scalar factor;
    secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(seckey != NULL);
    //ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&factor, tweak, &overflow);
    secp256k1_scalar_set_b32(&sec, seckey, NULL);
    ret = !overflow && secp256k1_eckey_privkey_tweak_mul(&sec, &factor);
    memset(seckey, 0, 32);
    if (ret) {
        secp256k1_scalar_get_b32(seckey, &sec);
    }

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&factor);
    return ret;
}

int secp256k1_ec_pubkey_tweak_mul(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    secp256k1_ge p;
    secp256k1_scalar factor;
    int ret = 0;
    int overflow = 0;
    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    //ARG_CHECK(pubkey != NULL);
    //ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&factor, tweak, &overflow);
    ret = !overflow && secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (secp256k1_eckey_pubkey_tweak_mul(&ctx->ecmult_ctx, &p, &factor)) {
            secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int secp256k1_context_randomize(secp256k1_context* ctx, const unsigned char *seed32) {
    //VERIFY_CHECK(ctx != NULL);
    //ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, seed32);
    return 1;
}

int secp256k1_ec_pubkey_combine(const secp256k1_context* ctx, secp256k1_pubkey *pubnonce, const secp256k1_pubkey * const *pubnonces, size_t n) {
    size_t i;
    secp256k1_gej Qj;
    secp256k1_ge Q;

    //ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    //ARG_CHECK(n >= 1);
    //ARG_CHECK(pubnonces != NULL);

    secp256k1_gej_set_infinity(&Qj);

    for (i = 0; i < n; i++) {
        secp256k1_pubkey_load(ctx, &Q, pubnonces[i]);
        secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    }
    if (secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&Q, &Qj);
    secp256k1_pubkey_save(pubnonce, &Q);
    return 1;
}

#ifdef ENABLE_MODULE_ECDH
# include "modules/ecdh/main_impl.h"
#endif

#ifdef ENABLE_MODULE_SCHNORR
# include "modules/schnorr/main_impl.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "modules/recovery/main_impl.h"
#endif

void generate_pubkeys(unsigned char*privkeys, unsigned char*pubkeys, int thread_id)
{
	static secp256k1_context *ctx[THREAD_QTY];
	static secp256k1_ecmult_big_context *bmul[THREAD_QTY];
	static secp256k1_scratch *scr[THREAD_QTY];
	int ret;

	if (privkeys == NULL || pubkeys == NULL)
	{
		ret = pthread_mutex_lock(&initMutex);
		if (ret) { /* an error has occurred */
		    perror("pthread_mutex_lock");
		    pthread_exit(NULL);
		}

		secp256k1_init(&ctx[thread_id], &bmul[thread_id], &scr[thread_id]);

		secp256k1_selfcheck(ctx[thread_id], bmul[thread_id], scr[thread_id]);

		full_stack_check(ctx[thread_id], bmul[thread_id], scr[thread_id]);

		ret = pthread_mutex_unlock(&initMutex);
		if (ret) { /* an error has occurred */
		    perror("pthread_mutex_unlock");
		    pthread_exit(NULL);
		}

	}
	else
	{
		int ret = secp256k1_ec_pubkey_create_serialized_batch(ctx[thread_id], bmul[thread_id], scr[thread_id], pubkeys, privkeys);
		if (ret == 0)
		{
			printf("generate_pubkeys : Returned 0.\n");
			exit(EXIT_FAILURE);
		}
	}
}

void rand_privkey(unsigned char *privkey) {
    // Not cryptographically secure, but good enough for quick verification tests
    for ( size_t pos = 0; pos < 32; pos++ ) {
        privkey[pos] = rand() & 0xFF;
    }
}

void *safe_calloc(size_t num, size_t size) {
    void *rtn = calloc(num, size);
    if ( !rtn ) {
        printf("calloc failed to allocate %zu items of size %zu\n", num, size);
        exit(EXIT_FAILURE);
    }
    return rtn;
}

void secp256k1_init(secp256k1_context** ctx, secp256k1_ecmult_big_context** bmul, secp256k1_scratch **scr)
{
	struct timespec clock_start ;
	double clock_diff;

    printf("bmul  size = %u\n", BMUL_BITS);

    printf("Initializing secp256k1 context\n");
    clock_start = get_clock();
    *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    clock_diff = get_clockdiff_s(clock_start);
    printf("main context = %12.8f\n", clock_diff);


    printf("Initializing secp256k1_ecmult_big context\n");
    clock_start = get_clock();
    *bmul = secp256k1_ecmult_big_create(*ctx);
    clock_diff = get_clockdiff_s(clock_start);
    printf("bmul context = %12.8f\n", clock_diff);
    printf("\n");


    // Initializing secp256k1_scratch for batched key calculations
    *scr = secp256k1_scratch_create(*ctx, batch_size);

}

int secp256k1_selfcheck(secp256k1_context* ctx, secp256k1_ecmult_big_context* bmul, secp256k1_scratch *scr)
{
    ////////////////////////////////////////////////////////////////////////////////
    //                                Verification                                //
    ////////////////////////////////////////////////////////////////////////////////

    size_t test_count = 1024;
    size_t expected_count;
    size_t actual_count;

    // Verify serial pubkey generation
    unsigned char *privkey  = (unsigned char*)safe_calloc(1, 32 * sizeof(unsigned char));
    unsigned char *expected = (unsigned char*)safe_calloc(1, 65 * sizeof(unsigned char));
    unsigned char *actual   = (unsigned char*)safe_calloc(1, 65 * sizeof(unsigned char));


    // Quick baseline test to make sure we can trust our "expected" results
    memcpy(privkey,  baseline_privkey,  32);
    memcpy(expected, baseline_expected, 65);

    expected_count = 1;
    actual_count   = secp256k1_ec_pubkey_create_serialized(ctx, NULL, actual, privkey);

    if ( actual_count != expected_count ) {
        printf("Baseline verification warning\n");
        printf("  expected count = %zu\n", expected_count);
        printf("  actual   count = %zu\n", actual_count);
    }

    if ( memcmp(expected, actual, 65) != 0 ) {
        printf("Baseline verification failed\n");
        return 1;
    }
    printf("Baseline verification passed\n");


    // Verify that using the faster bmul context returns correct results
    for ( size_t iter = 0; iter < test_count; iter++ ) {
        rand_privkey(privkey);

        // Known working result
        expected_count = secp256k1_ec_pubkey_create_serialized(ctx, NULL, expected, privkey);

        // Method being tested
        actual_count   = secp256k1_ec_pubkey_create_serialized(ctx, bmul, actual,   privkey);


        if ( expected_count != actual_count ) {
            printf("Serial verification warning on iteration %zu\n", iter);
            printf("  expected count = %zu\n", expected_count);
            printf("  actual   count = %zu\n", actual_count);
        }

        if ( memcmp(expected, actual, 65) != 0 ) {
            printf("Serial verification failed on iteration %zu\n", iter);
			hexdump_bytes_hn("  privkey  = ", privkey,  32); printf("\n");
			hexdump_bytes_hn("  expected = ", expected, 65); printf("\n");
			hexdump_bytes_hn("  actual   = ", actual,   65); printf("\n");
            return 1;
        }
    }

    free(privkey); free(expected); free(actual);
    printf("Serial verification passed\n");


    // Verify batched pubkey generation
    // If we made it this far, we can trust ecmult_big results, so we'll
    //   use it to make this part of the verification go a little faster
    privkey  = (unsigned char*)safe_calloc(batch_size, 32 * sizeof(unsigned char));
    expected = (unsigned char*)safe_calloc(batch_size, 65 * sizeof(unsigned char));
    actual   = (unsigned char*)safe_calloc(batch_size, 65 * sizeof(unsigned char));

    for ( size_t batch = 0; batch < test_count / batch_size; batch++ ) {
        expected_count = 0;

        for ( size_t i = 0; i < batch_size; i++ ) {
            rand_privkey(&privkey[32 * i]);
            expected_count += secp256k1_ec_pubkey_create_serialized(ctx, bmul, &expected[65 * i], &privkey[32 * i]);
        }

        actual_count = secp256k1_ec_pubkey_create_serialized_batch(ctx, bmul, scr, actual, privkey);


        if ( expected_count != actual_count ) {
            printf("Batch verification warning on batch %zu\n", batch);
            printf("  expected count = %zu\n", expected_count);
            printf("  actual   count = %zu\n", actual_count);
        }

        for ( size_t i = 0; i < batch_size; i++ ) {
            unsigned char *p = &( privkey[32 * i]);
            unsigned char *e = &(expected[65 * i]);
            unsigned char *a = &(  actual[65 * i]);

            if ( memcmp(e, a, 65) != 0 ) {
                printf("Batch verification failed on batch %zu item %zu\n", batch, i);
				hexdump_bytes_hn("  privkey  = ", p,  32); printf("\n");
				hexdump_bytes_hn("  expected = ", e, 65); printf("\n");
				hexdump_bytes_hn("  actual   = ", a,   65); printf("\n");
                return 1;
            }
        }
    }

    free(privkey); free(expected); free(actual);
    printf("Batched verification passed\n");
    printf("\n");
    return 0;
}



static void secp256k1_ecmult_gen_context_init(secp256k1_ecmult_gen_context *ctx) {
    ctx->prec = NULL;
}

static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context *ctx, const secp256k1_callback* cb) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    secp256k1_ge prec[1024];
    secp256k1_gej gj;
    secp256k1_gej nums_gej;
    int i, j;
#endif

    if (ctx->prec != NULL) {
        return;
    }
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    ctx->prec = (secp256k1_ge_storage (*)[64][16])checked_malloc(cb, sizeof(*ctx->prec));

    /* get the generator */
    secp256k1_gej_set_ge(&gj, &secp256k1_ge_const_g);

    /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
    {
        static const unsigned char nums_b32[33] = "The scalar for this x is unknown";
        secp256k1_fe nums_x;
        secp256k1_ge nums_ge;
        int r;
        r = secp256k1_fe_set_b32(&nums_x, nums_b32);
        (void)r;
        VERIFY_CHECK(r);
        r = secp256k1_ge_set_xo_var(&nums_ge, &nums_x, 0);
        (void)r;
        VERIFY_CHECK(r);
        secp256k1_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        secp256k1_gej_add_ge_var(&nums_gej, &nums_gej, &secp256k1_ge_const_g, NULL);
    }

    /* prec is calculated as a 1024 element array but will be treated as prec[64][16].                          */
    /* We shall call the first index the "window" index:                                                        */
    /*   It corresponds to the 4-bit "window" position of the input scalar that we're multiplying against.      */
    /* The second index is the "bits" index:                                                                    */
    /*   It corresponds to the actual raw bits shifted off the scalar.  We use 4-bit windows, so 2^4 values.    */
    /* This gives us prec[window][bits].                                                                        */
    /*                                                                                                          */
    /* Each row, prec[window][*] starts with (16^window * G) and each column is the previous + G.               */
    /* This means we can extract 4 bits at a time from the scalar, look up the element associated with          */
    /*   those bits at that window position, then add it to our accumulated result.                             */
    /* This gives us: result = sum(prec[window][shift(scalar, 4)], window = 0 to 63)                            */
    /*                                                                                                          */
    /* Furthermore, each window has (2^window * blind) added to it.                                             */
    /* This is probably to ensure that there won't be any point at infinity values in the prec table.           */
    /* This also has the unfortunate side effect of:                                                            */
    /*   1) No additions can be skipped (X + inf = X, but now we have no points at infinity)                    */
    /*   2) Each row in the prec table shifts the result by 2^window * blind                                    */
    /* Because of #2, the final row of the table uses (1-2^window) * blind:                                     */
    /*   blind * (1b + 10b + ... + 10..0b + -11..1b) = blind * 0                                                */

    /* compute prec. */
    {
        secp256k1_gej precj[1024]; /* Jacobian versions of prec. */
        secp256k1_gej gbase;
        secp256k1_gej numsbase;
        gbase = gj; /* 16^j * G */
        numsbase = nums_gej; /* 2^j * nums. */
        for (j = 0; j < 64; j++) {
            /* Set precj[j*16 .. j*16+15] to (numsbase, numsbase + gbase, ..., numsbase + 15*gbase). */
            precj[j*16] = numsbase;
            for (i = 1; i < 16; i++) {
                secp256k1_gej_add_var(&precj[j*16 + i], &precj[j*16 + i - 1], &gbase, NULL);
            }
            /* Multiply gbase by 16. */
            for (i = 0; i < 4; i++) {
                secp256k1_gej_double_var(&gbase, &gbase, NULL);
            }
            /* Multiply numbase by 2. */
            secp256k1_gej_double_var(&numsbase, &numsbase, NULL);
            if (j == 62) {
                /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                secp256k1_gej_neg(&numsbase, &numsbase);
                secp256k1_gej_add_var(&numsbase, &numsbase, &nums_gej, NULL);
            }
        }
        secp256k1_ge_set_all_gej_var(1024, prec, precj, cb);
    }
    for (j = 0; j < 64; j++) {
        for (i = 0; i < 16; i++) {
            secp256k1_ge_to_storage(&(*ctx->prec)[j][i], &prec[j*16 + i]);
        }
    }
#else
    (void)cb;
    ctx->prec = (secp256k1_ge_storage (*)[64][16])secp256k1_ecmult_static_context;
#endif
    secp256k1_ecmult_gen_blind(ctx, NULL);
}


static void secp256k1_ecmult_gen_context_clone(secp256k1_ecmult_gen_context *dst,
                                               const secp256k1_ecmult_gen_context *src, const secp256k1_callback* cb) {
    if (src->prec == NULL) {
        dst->prec = NULL;
    } else {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
        dst->prec = (secp256k1_ge_storage (*)[64][16])checked_malloc(cb, sizeof(*dst->prec));
        memcpy(dst->prec, src->prec, sizeof(*dst->prec));
#else
        (void)cb;
        dst->prec = src->prec;
#endif
        dst->initial = src->initial;
        dst->blind = src->blind;
    }
}

static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context *ctx) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    free(ctx->prec);
#endif
    secp256k1_scalar_clear(&ctx->blind);
    secp256k1_gej_clear(&ctx->initial);
    ctx->prec = NULL;
}

static void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
    secp256k1_ge add;
    /* secp256k1_ge_storage adds; */
    secp256k1_scalar gnb;
    int bits;
    int /* i, */ j;

    /* memset(&adds, 0, sizeof(adds)); */
    *r = ctx->initial;

    /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
    secp256k1_scalar_add(&gnb, gn, &ctx->blind);
    add.infinity = 0;

    for (j = 0; j < 64; j++) {
        bits = secp256k1_scalar_get_bits(&gnb, j * 4, 4);
#if 0
        for (i = 0; i < 16; i++) {
            /** This uses a conditional move to avoid any secret data in array indexes.
             *   _Any_ use of secret indexes has been demonstrated to result in timing
             *   sidechannels, even when the cache-line access patterns are uniform.
             *  See also:
             *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
             *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
             *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
             *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
             *    (http://www.tau.ac.il/~tromer/papers/cache.pdf)
             */
            secp256k1_ge_storage_cmov(&adds, &(*ctx->prec)[j][i], i == bits);
        }
        secp256k1_ge_from_storage(&add, &adds);
#endif
        secp256k1_ge_from_storage(&add, &(*ctx->prec)[j][bits]);
        secp256k1_gej_add_ge(r, r, &add);
    }

#if 0
    bits = 0;
    secp256k1_ge_clear(&add);
    secp256k1_scalar_clear(&gnb);
#endif
}

/* Setup blinding values for secp256k1_ecmult_gen. */
static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
    secp256k1_scalar b;
    secp256k1_gej gb;
    secp256k1_fe s;
    unsigned char nonce32[32];
    secp256k1_rfc6979_hmac_sha256_t rng;
    int retry;
    unsigned char keydata[64] = {0};
    if (seed32 == NULL) {
        /* When seed is NULL, reset the initial point and blinding value. */
        secp256k1_gej_set_ge(&ctx->initial, &secp256k1_ge_const_g);
        secp256k1_gej_neg(&ctx->initial, &ctx->initial);
        secp256k1_scalar_set_int(&ctx->blind, 1);
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    secp256k1_scalar_get_b32(nonce32, &ctx->blind);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    memcpy(keydata, nonce32, 32);
    if (seed32 != NULL) {
        memcpy(keydata + 32, seed32, 32);
    }
    secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, seed32 ? 64 : 32);
    /* memset(keydata, 0, sizeof(keydata)); */
    /* Retry for out of range results to achieve uniformity. */
    do {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        retry = !secp256k1_fe_set_b32(&s, nonce32);
        retry |= secp256k1_fe_is_zero(&s);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > Fp. */
    /* Randomize the projection to defend against multiplier sidechannels. */
    secp256k1_gej_rescale(&ctx->initial, &s);
    secp256k1_fe_clear(&s);
    do {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        secp256k1_scalar_set_b32(&b, nonce32, &retry);
        /* A blinding value of 0 works, but would undermine the projection hardening. */
        retry |= secp256k1_scalar_is_zero(&b);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > order. */
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    /* memset(nonce32, 0, 32); */
    secp256k1_ecmult_gen(ctx, &gb, &b);
    secp256k1_scalar_negate(&b, &b);
    ctx->blind = b;
    ctx->initial = gb;
    secp256k1_scalar_clear(&b);
    secp256k1_gej_clear(&gb);
}







static int secp256k1_eckey_pubkey_parse(secp256k1_ge *elem, const unsigned char *pub, size_t size) {
    if (size == 33 && (pub[0] == 0x02 || pub[0] == 0x03)) {
        secp256k1_fe x;
        return secp256k1_fe_set_b32(&x, pub+1) && secp256k1_ge_set_xo_var(elem, &x, pub[0] == 0x03);
    } else if (size == 65 && (pub[0] == 0x04 || pub[0] == 0x06 || pub[0] == 0x07)) {
        secp256k1_fe x, y;
        if (!secp256k1_fe_set_b32(&x, pub+1) || !secp256k1_fe_set_b32(&y, pub+33)) {
            return 0;
        }
        secp256k1_ge_set_xy(elem, &x, &y);
        if ((pub[0] == 0x06 || pub[0] == 0x07) && secp256k1_fe_is_odd(&y) != (pub[0] == 0x07)) {
            return 0;
        }
        return secp256k1_ge_is_valid_var(elem);
    } else {
        return 0;
    }
}

static int secp256k1_eckey_pubkey_serialize(secp256k1_ge *elem, unsigned char *pub) {
    if (secp256k1_ge_is_infinity(elem)) {
        return 0;
    }
    secp256k1_fe_normalize_var(&elem->x);
    secp256k1_fe_normalize_var(&elem->y);
    secp256k1_fe_get_b32(&pub[1], &elem->x);
	pub[0] = 0x04;
	secp256k1_fe_get_b32(&pub[33], &elem->y);
    return 1;
}

static int secp256k1_eckey_privkey_tweak_add(secp256k1_scalar *key, const secp256k1_scalar *tweak) {
    secp256k1_scalar_add(key, key, tweak);
    if (secp256k1_scalar_is_zero(key)) {
        return 0;
    }
    return 1;
}

static int secp256k1_eckey_pubkey_tweak_add(const secp256k1_ecmult_context *ctx, secp256k1_ge *key, const secp256k1_scalar *tweak) {
    secp256k1_gej pt;
    secp256k1_scalar one;
    secp256k1_gej_set_ge(&pt, key);
    secp256k1_scalar_set_int(&one, 1);
    secp256k1_ecmult(ctx, &pt, &pt, &one, tweak);

    if (secp256k1_gej_is_infinity(&pt)) {
        return 0;
    }
    secp256k1_ge_set_gej(key, &pt);
    return 1;
}

static int secp256k1_eckey_privkey_tweak_mul(secp256k1_scalar *key, const secp256k1_scalar *tweak) {
    if (secp256k1_scalar_is_zero(tweak)) {
        return 0;
    }

    secp256k1_scalar_mul(key, key, tweak);
    return 1;
}

static int secp256k1_eckey_pubkey_tweak_mul(const secp256k1_ecmult_context *ctx, secp256k1_ge *key, const secp256k1_scalar *tweak) {
    secp256k1_scalar zero;
    secp256k1_gej pt;
    if (secp256k1_scalar_is_zero(tweak)) {
        return 0;
    }

    secp256k1_scalar_set_int(&zero, 0);
    secp256k1_gej_set_ge(&pt, key);
    secp256k1_ecmult(ctx, &pt, &pt, tweak, &zero);
    secp256k1_ge_set_gej(key, &pt);
    return 1;
}






/** Create a secp256k1 ecmult big context.
 *
 *  Returns: a newly created ecmult big context.
 *  Args:   ctx:    pointer to a context object, initialized for signing (cannot be NULL)
 *  In:     bits:   the window size in bits for the precomputation table
 */
secp256k1_ecmult_big_context* secp256k1_ecmult_big_create(const secp256k1_context* ctx) {
    unsigned int windows;
    size_t window_size, total_size;
    size_t i, row;

    secp256k1_fe  fe_zinv;
    secp256k1_ge  ge_temp;
    secp256k1_ge  ge_window_one = secp256k1_ge_const_g;
    secp256k1_gej gej_window_base;
    secp256k1_ecmult_big_context *rtn;


    /* We +1 to account for a possible high 1 bit after converting the privkey to signed digit form.    */
    /* This means our table reaches to 257 bits even though the privkey scalar is at most 256 bits.     */
    windows = (256 / BMUL_BITS) + 1;
    window_size = (1 << (BMUL_BITS - 1));

    /* Total number of required point storage elements.                                 */
    /* This differs from the (windows * window_size) because the last row can be shrunk */
    /*   as it only needs to extend enough to include a possible 1 in the 257th bit.    */
    total_size = (256 / BMUL_BITS) * window_size + (1 << (256 % BMUL_BITS));



    /**************** Allocate Struct Members *****************/
    rtn = (secp256k1_ecmult_big_context *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ecmult_big_context));
    *(unsigned int *)(&rtn->bits) = BMUL_BITS;
    *(unsigned int *)(&rtn->windows) = windows;

    /* An array of secp256k1_ge_storage pointers, one for each window. */
    rtn->precomp = (secp256k1_ge_storage **)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge_storage *) * windows);

    /* Bulk allocate up front.  We'd rather run out of memory now than during computation.  */
    /* Only the 0th row is malloc'd, the rest will be updated to point to row starts        */
    /*   within the giant chunk of memory that we've allocated.                             */
    rtn->precomp[0] = (secp256k1_ge_storage *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge_storage) * total_size);

    /* Each row starts window_size elements after the previous. */
    for ( i = 1; i < windows; i++ ) { rtn->precomp[i] = (rtn->precomp[i - 1] + window_size); }

    rtn->gej_temp = (secp256k1_gej *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_gej) * window_size);
    rtn->z_ratio  = (secp256k1_fe  *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_fe ) * window_size);



    /************ Precomputed Table Initialization ************/
    secp256k1_gej_set_ge(&gej_window_base, &ge_window_one);

    /* This is the same for all windows.    */
    secp256k1_fe_set_int(&(rtn->z_ratio[0]), 0);


    for ( row = 0; row < windows; row++ ) {
        /* The last row is a bit smaller, only extending to include the 257th bit. */
        window_size = ( row == windows - 1 ? (1 << (256 % BMUL_BITS)) : (1 << (BMUL_BITS - 1)) );

        /* The base element of each row is 2^bits times the previous row's base. */
        if ( row > 0 ) {
            for ( i = 0; i < BMUL_BITS; i++ ) { secp256k1_gej_double_var(&gej_window_base, &gej_window_base, NULL); }
        }
        rtn->gej_temp[0] = gej_window_base;

        /* The base element is also our "one" value for this row.   */
        /* If we are at offset 2^X, adding "one" should add 2^X.    */
        secp256k1_ge_set_gej(&ge_window_one, &gej_window_base);


        /* Repeated + 1s to fill the rest of the row.   */

        /* We capture the Z ratios between consecutive points for quick Z inversion.    */
        /*   gej_temp[i-1].z * z_ratio[i] => gej_temp[i].z                              */
        /* This means that z_ratio[i] = (gej_temp[i-1].z)^-1 * gej_temp[i].z            */
        /* If we know gej_temp[i].z^-1, we can get gej_temp[i-1].z^1 using z_ratio[i]   */
        /* Visually:                                    */
        /* i            0           1           2       */
        /* gej_temp     a           b           c       */
        /* z_ratio     NaN      (a^-1)*b    (b^-1)*c    */
        for ( i = 1; i < window_size; i++ ) {
            secp256k1_gej_add_ge_var(&(rtn->gej_temp[i]), &(rtn->gej_temp[i-1]), &ge_window_one, &(rtn->z_ratio[i]));
        }


        /* An unpacked version of secp256k1_ge_set_table_gej_var() that works   */
        /*   element by element instead of requiring a secp256k1_ge *buffer.    */

        /* Invert the last Z coordinate manually.   */
        i = window_size - 1;
        secp256k1_fe_inv(&fe_zinv, &(rtn->gej_temp[i].z));
        secp256k1_ge_set_gej_zinv(&ge_temp, &(rtn->gej_temp[i]), &fe_zinv);
        secp256k1_ge_to_storage(&(rtn->precomp[row][i]), &ge_temp);

        /* Use the last element's known Z inverse to determine the previous' Z inverse. */
        for ( ; i > 0; i-- ) {
            /* fe_zinv = (gej_temp[i].z)^-1                 */
            /* (gej_temp[i-1].z)^-1 = z_ratio[i] * fe_zinv  */
            secp256k1_fe_mul(&fe_zinv, &fe_zinv, &(rtn->z_ratio[i]));
            /* fe_zinv = (gej_temp[i-1].z)^-1               */

            secp256k1_ge_set_gej_zinv(&ge_temp, &(rtn->gej_temp[i-1]), &fe_zinv);
            secp256k1_ge_to_storage(&(rtn->precomp[row][i-1]), &ge_temp);
        }
    }


    /* We won't be using these any more.    */
    free(rtn->gej_temp); rtn->gej_temp = NULL;
    free(rtn->z_ratio);  rtn->z_ratio  = NULL;

    return rtn;
}


/** Destroy a secp256k1 ecmult big context.
 *
 *  The context pointer may not be used afterwards.
 *  Args:   bmul:   an existing context to destroy (cannot be NULL)
 */
void secp256k1_ecmult_big_destroy(secp256k1_ecmult_big_context* bmul) {
    //VERIFY_CHECK(bmul != NULL);
    //if ( bmul == NULL ) { return; }

    /* Just in case the caller tries to use after free. */
    *(unsigned int *)(&bmul->bits)    = 0;
    *(unsigned int *)(&bmul->windows) = 0;

    if ( bmul->precomp != NULL ) {
        /* This was allocated with a single malloc, it will be freed with a single free. */
        if ( bmul->precomp[0] != NULL ) { free(bmul->precomp[0]); bmul->precomp[0] = NULL; }

        free(bmul->precomp); bmul->precomp = NULL;
    }

    /* These should already be freed, but just in case. */
    if ( bmul->gej_temp != NULL ) { free(bmul->gej_temp); bmul->gej_temp = NULL; }
    if ( bmul->z_ratio  != NULL ) { free(bmul->z_ratio ); bmul->z_ratio  = NULL; }

    free(bmul);
}



/** Shifts and returns the first N <= 64 bits from a scalar.
 *  The default secp256k1_scalar_shr_int only handles up to 15 bits.
 *
 *  Args:   s:      a scalar object to shift from (cannot be NULL)
 *  In:     n:      number of bits to shift off and return
 */
uint64_t secp256k1_scalar_shr_any(secp256k1_scalar *s, unsigned int n) {
    unsigned int cur_shift = 0, offset = 0;
    uint64_t rtn = 0;

    VERIFY_CHECK(s != NULL);
    VERIFY_CHECK(n >   0);
    VERIFY_CHECK(n <= 64);

    while ( n > 0 ) {
        /* Shift up to 15 bits at a time, or N bits, whichever is smaller.  */
        /* secp256k1_scalar_shr_int() is hard limited to (0 < n < 16).      */
        cur_shift = ( n > 15 ? 15 : n );

        rtn |= ((uint64_t)secp256k1_scalar_shr_int(s, cur_shift) << (uint64_t)offset);

        offset += cur_shift;
        n      -= cur_shift;
    }

    return rtn;
}


/** Converts the lowest w-bit window of scalar s into signed binary form
 *
 *  Returns: signed form of the lowest w-bit window
 *  Args:   s:  scalar to read from and modified (cannot be NULL)
 *  In:     w:  window size in bits (w < 64)
 */
static int64_t secp256k1_scalar_sdigit_single(secp256k1_scalar *s, unsigned int w) {
    int64_t sdigit = 0;

    /* Represents a 1 bit in the next window's least significant bit.       */
    /* VERIFY_CHECK verifies that (1 << w) won't touch int64_t's sign bit.  */
    int64_t overflow_bit = (int64_t)(1 << w);

    /* Represents the maximum positive value in a w-bit precomp table.  */
    /* Values greater than this are converted to negative values and    */
    /*   will "reverse borrow" a bit from the next window.              */
    int64_t precomp_max = (int64_t)(1 << (w-1));

    VERIFY_CHECK(s != NULL);
    VERIFY_CHECK(w >=  1);
    VERIFY_CHECK(w <= 62);

    sdigit = (int64_t)secp256k1_scalar_shr_any(s, w);

    if ( sdigit <= precomp_max ) {
        /* A w-bit precomp table has this digit as a positive value, return as-is.  */
        return sdigit;

    } else {
        secp256k1_scalar one;
        secp256k1_scalar_set_int(&one, 1);

        /* Convert this digit to a negative value, but balance s by adding it's value.  */
        /* Subtracting our sdigit value carries over into a 1 bit of the next digit.    */
        /* Since s has been shifted down w bits, s += 1 does the same thing.            */
        sdigit -= overflow_bit;

        secp256k1_scalar_add(s, s, &one);

        return sdigit;
    }
}



/** Multiply with the generator: R = a*G.
 *
 *  Args:   bmul:   pointer to an ecmult_big_context (cannot be NULL)
 *  Out:    r:      set to a*G where G is the generator (cannot be NULL)
 *  In:     a:      the scalar to multiply the generator by (cannot be NULL)
 */
static void secp256k1_ecmult_big(const secp256k1_ecmult_big_context* bmul, secp256k1_gej *r, const secp256k1_scalar *a) {
    size_t  window = 0;
    int64_t sdigit = 0;
    secp256k1_ge window_value;

    /* Copy of the input scalar which secp256k1_scalar_sdigit_single will destroy. */
    secp256k1_scalar privkey = *a;

    VERIFY_CHECK(bmul != NULL);
    VERIFY_CHECK(bmul->bits > 0);
    VERIFY_CHECK(r != NULL);
    VERIFY_CHECK(a != NULL);

    /* Until we hit a non-zero window, the value of r is undefined. */
    secp256k1_gej_set_infinity(r);

    /* If the privkey is zero, bail. */
    if ( secp256k1_scalar_is_zero(&privkey) ) { return; }


    /* Incrementally convert the privkey into signed digit form, one window at a time. */
    while ( window < bmul->windows && !secp256k1_scalar_is_zero(&privkey) ) {
        sdigit = secp256k1_scalar_sdigit_single(&privkey, bmul->bits);

        /* Zero windows have no representation in our precomputed table. */
        if ( sdigit != 0 ) {
            if ( sdigit < 0 ) {
                /* Use the positive precomp index and negate the result. */
                secp256k1_ge_from_storage(&window_value, &(bmul->precomp[window][ -(sdigit) - 1 ]));
                secp256k1_ge_neg(&window_value, &window_value);
            } else {
                /* Use the precomp index and result as-is.  */
                secp256k1_ge_from_storage(&window_value, &(bmul->precomp[window][ +(sdigit) - 1 ]));
            }

            /* The first addition is automatically replaced by a load when r = inf. */
            secp256k1_gej_add_ge_var(r, r, &window_value, NULL);
        }

        window++;
    }

    /* If privkey isn't zero, something broke.  */
    VERIFY_CHECK(secp256k1_scalar_is_zero(&privkey));
}

secp256k1_scratch* secp256k1_scratch_create(const secp256k1_context* ctx, const size_t size) {
    secp256k1_scratch* rtn = (secp256k1_scratch *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_scratch));

    /* Cast away const-ness to set the size value.  */
    /* http://stackoverflow.com/a/9691556/477563    */
    *(size_t *)&rtn->size = size;

    rtn->gej    = (secp256k1_gej*)checked_malloc(&ctx->error_callback, sizeof(secp256k1_gej) * size);
    rtn->fe_in  = (secp256k1_fe *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_fe ) * size);
    rtn->fe_out = (secp256k1_fe *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_fe ) * size);

    return rtn;
}


void secp256k1_scratch_destroy(secp256k1_scratch* scr) {
    if (scr != NULL) {
        /* Just in case the caller tries to reuse this scratch space, set size to zero.     */
        /* Functions that use this scratch space will reject scratches that are undersized. */
        *(size_t *)&scr->size = 0;

        if ( scr->gej    != NULL ) { free(scr->gej   ); scr->gej    = NULL; }
        if ( scr->fe_in  != NULL ) { free(scr->fe_in ); scr->fe_in  = NULL; }
        if ( scr->fe_out != NULL ) { free(scr->fe_out); scr->fe_out = NULL; }

        free(scr);
    }
}



size_t secp256k1_ec_pubkey_create_serialized(const secp256k1_context *ctx, const secp256k1_ecmult_big_context *bmul, unsigned char *pubkey, const unsigned char *privkey) {
    /* Creating our own 1 element scratch structure. */
    secp256k1_gej gej;
    secp256k1_fe  fe_in, fe_out;

    secp256k1_scalar s_privkey;
    secp256k1_ge ge_pubkey;

	/* Convert private key to scalar form. */
	secp256k1_scalar_set_b32(&s_privkey, privkey, NULL);

	/* Multiply the private key by the generator point. */
	if ( bmul != NULL ) {
		/* Multiplication using larger, faster, precomputed tables. */
		secp256k1_ecmult_big(bmul, &gej, &s_privkey);
	} else {
		/* Multiplication using default implementation. */
		secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &gej, &s_privkey);
	}

	/* Save the Jacobian pubkey's Z coordinate for batch inversion. */
	fe_in = gej.z;

	/* Invert all Jacobian public keys' Z values in one go. */
	secp256k1_fe_inv_all_var(1, &fe_out, &fe_in);


	 /* Otherwise, load the next inverted Z value and convert the pubkey to affine coordinates. */
	secp256k1_ge_set_gej_zinv(&ge_pubkey, &gej, &fe_out);

	/* Serialize the public key into the requested format. */
	secp256k1_eckey_pubkey_serialize(&ge_pubkey, pubkey);


    /* Returning the number of successfully converted private keys. */
    return 1;
}


size_t secp256k1_ec_pubkey_create_serialized_batch(const secp256k1_context *ctx, const secp256k1_ecmult_big_context *bmul, secp256k1_scratch *scr, unsigned char *pubkeys, const unsigned char *privkeys) {
    secp256k1_scalar s_privkey;
    secp256k1_ge ge_pubkey;
    size_t i, out_keys;

    /* Argument checking. */
    /*
    ARG_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    ARG_CHECK(scr         != NULL);
    ARG_CHECK(scr->gej    != NULL);
    ARG_CHECK(scr->fe_in  != NULL);
    ARG_CHECK(scr->fe_out != NULL);

    ARG_CHECK(pubkeys  != NULL);

    ARG_CHECK(privkeys != NULL);

    ARG_CHECK(key_count <= scr->size);
     */

    /* Blank all of the output, regardless of what happens.                 */
    /* This marks all output keys as invalid until successfully created.    */
    //memset(pubkeys, 0, sizeof(*pubkeys) * pubkey_size * key_count);

    out_keys = 0;

    for ( i = 0; i < batch_size; i++ ) {
    	//s_privkey = &(privkeys[32 * i]);
        /* Convert private key to scalar form. */
        secp256k1_scalar_set_b32(&s_privkey, &(privkeys[32 * i]), NULL);

        /* Reject the privkey if it's zero or has reduced to zero. */
        /* Mark the corresponding Jacobian pubkey as infinity so we know to skip this key later. */
        if ( secp256k1_scalar_is_zero(&s_privkey) ) {
            scr->gej[i].infinity = 1;
            continue;
        }


        /* Multiply the private key by the generator point. */
        if ( bmul != NULL ) {
            /* Multiplication using larger, faster, precomputed tables. */
            secp256k1_ecmult_big(bmul, &(scr->gej[i]), &s_privkey);
        } else {
            /* Multiplication using default implementation. */
            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &(scr->gej[i]), &s_privkey);
        }

        /* If the result is the point at infinity, the pubkey is invalid. */
        if ( scr->gej[i].infinity ) { continue; }


        /* Save the Jacobian pubkey's Z coordinate for batch inversion. */
        scr->fe_in[out_keys] = scr->gej[i].z;
        out_keys++;
    }


    /* Assuming we have at least one non-infinite Jacobian pubkey. */
    if ( out_keys > 0 ) {
        /* Invert all Jacobian public keys' Z values in one go. */
        secp256k1_fe_inv_all_var(out_keys, scr->fe_out, scr->fe_in);
    }


    /* Using the inverted Z values, convert each Jacobian public key to affine, */
    /*   then serialize the affine version to the pubkey buffer.                */
    out_keys = 0;

    for ( i = 0; i < batch_size; i++) {
        /* Skip inverting infinite values. */
        /* The corresponding pubkey is already filled with \0 bytes from earlier. */
        if ( scr->gej[i].infinity ) {
            continue;
        }

        /* Otherwise, load the next inverted Z value and convert the pubkey to affine coordinates. */
        secp256k1_ge_set_gej_zinv(&ge_pubkey, &(scr->gej[i]), &(scr->fe_out[out_keys]));

        /* Serialize the public key into the requested format. */
        secp256k1_eckey_pubkey_serialize(&ge_pubkey, &(pubkeys[PUBLIC_KEY_LENGTH * i]));
        out_keys++;
    }


    /* Returning the number of successfully converted private keys. */
    return out_keys;
}

int full_stack_check(secp256k1_context* ctx, const secp256k1_ecmult_big_context *bmul, secp256k1_scratch *scr)
{
	const char * privkey = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
	const char * pubkey_u = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6";
	const char * pubkey_c = "0250863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B235";
	const char * pubkey_u_hash256 = "600FFE422B4E00731A59557A5CCA46CC183944191006324A447BDB2D98D4B408";
	const char * pubkey_c_hash256 = "";
	const char * pubkey_u_hash160 = "010966776006953D5567439E5E39F86A0D273BEE";
	const char * pubkey_c_hash160 = "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31";

	unsigned char privkey_bin[batch_size*PRIVATE_KEY_LENGTH] 		;
	unsigned char pubkey_u_bin[PUBLIC_KEY_LENGTH] 		;
	unsigned char pubkey_c_bin [PUBLIC_COMPRESSED_KEY_LENGTH]		;
	unsigned char pubkey_u_hash256_bin[SHA256_HASH_SIZE];
	unsigned char pubkey_c_hash256_bin[SHA256_HASH_SIZE];
	unsigned char pubkey_u_hash160_bin[PUBLIC_KEY_HASH160_LENGTH];
	unsigned char pubkey_c_hash160_bin[PUBLIC_KEY_HASH160_LENGTH];
    unsigned char actual[batch_size*PUBLIC_KEY_LENGTH];

	struct timespec clock_start ;
	double clock_diff;
	int i,j;

    hex2bin(pubkey_u_bin, pubkey_u);
	hex2bin(pubkey_c_bin, pubkey_c);
	hex2bin(pubkey_u_hash256_bin, pubkey_u_hash256);
	hex2bin(pubkey_c_hash256_bin, pubkey_c_hash256);
	hex2bin(pubkey_u_hash160_bin, pubkey_u_hash160);
	hex2bin(pubkey_c_hash160_bin, pubkey_c_hash160);

	for (j=0 ; j<batch_size ; j++)
    {
    	hex2bin(&privkey_bin[j], privkey);
    }

    printf("Initializing Full Stack check\n");
    clock_start = get_clock();

    for (i=0 ; i<test_qty ; i++)
    {
		if(secp256k1_ec_pubkey_create_serialized_batch(ctx, bmul, scr, actual, (const unsigned char *)privkey_bin));
		/*
		if (memcmp(actual, pubkey_u_bin, PUBLIC_KEY_LENGTH) !=0)
		{
			printf("BitcoinCheck: Privkey -> Pubkey = FAIL\n");
			hexdump_bytes_hn("Actual  :", actual, PUBLIC_KEY_LENGTH);printf("\n");
			hexdump_bytes_hn("Expected:", (unsigned char*)pubkey_u_bin, PUBLIC_KEY_LENGTH);
			exit(EXIT_FAILURE);
		}
		*/
		//printf("BitcoinCheck: Privkey -> Pubkey = OK\n");

		sha256_hash_message((uint8_t*)pubkey_u_bin, PUBLIC_KEY_LENGTH, (uint32_t*)actual);
		/*
		if (memcmp(actual, pubkey_u_hash256_bin, SHA256_HASH_SIZE) !=0)
		{
			printf("BitcoinCheck: Privkey -> Pubkey -> SHA256 = FAIL\n");
			hexdump_bytes_hn("Actual  :", actual, SHA256_HASH_SIZE);printf("\n");
			hexdump_bytes_hn("Expected:", (unsigned char*)pubkey_u_hash256_bin, SHA256_HASH_SIZE);
			exit(EXIT_FAILURE);
		}
		*/
		//printf("BitcoinCheck: Privkey -> Privkey -> SHA256 = OK\n");

		ripemd160(pubkey_u_hash256_bin, SHA256_HASH_SIZE, actual);
		if (memcmp(actual, pubkey_u_hash160_bin, PUBLIC_KEY_HASH160_LENGTH) !=0)
		{
			printf("BitcoinCheck: Privkey -> Pubkey -> SHA256 -> RIPEMD160 = FAIL\n");
			hexdump_bytes_hn("Actual  :", actual, PUBLIC_KEY_HASH160_LENGTH);
			hexdump_bytes_hn("Expected:", (unsigned char*)pubkey_u_hash160_bin, PUBLIC_KEY_HASH160_LENGTH);
			exit(EXIT_FAILURE);
		}
		//printf("BitcoinCheck: Privkey -> Privkey -> SHA256 -> RIPEMD160 = OK\n");
    }
	clock_diff = get_clockdiff_s(clock_start);
	printf("Full Stack %d Priv/Pub key hash = %12.8fs = %12.4fH/sec\n", batch_size*test_qty, clock_diff, batch_size*test_qty/clock_diff);

	return 0;

}



