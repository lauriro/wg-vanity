/* wg-vanity - vanity WireGuard key generator
 * This is free software released into the public domain. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

/* Field arithmetic mod p = 2^255-19, radix 2^51 */

typedef uint64_t fe[5];

#define MASK51 ((1ULL << 51) - 1)

static void fe_0(fe r) { r[0]=r[1]=r[2]=r[3]=r[4]=0; }
static void fe_1(fe r) { r[0]=1; r[1]=r[2]=r[3]=r[4]=0; }
static void fe_copy(fe r, const fe a) {
	r[0]=a[0]; r[1]=a[1]; r[2]=a[2]; r[3]=a[3]; r[4]=a[4];
}

static void fe_add(fe r, const fe a, const fe b) {
	r[0] = a[0] + b[0];
	r[1] = a[1] + b[1];
	r[2] = a[2] + b[2];
	r[3] = a[3] + b[3];
	r[4] = a[4] + b[4];
}

static void fe_sub(fe r, const fe a, const fe b) {
	r[0] = a[0] + 0xFFFFFFFFFFFDAULL - b[0];
	r[1] = a[1] + 0xFFFFFFFFFFFFEULL - b[1];
	r[2] = a[2] + 0xFFFFFFFFFFFFEULL - b[2];
	r[3] = a[3] + 0xFFFFFFFFFFFFEULL - b[3];
	r[4] = a[4] + 0xFFFFFFFFFFFFEULL - b[4];
}

static void fe_reduce(fe r) {
	uint64_t c;
	c = r[0] >> 51; r[0] &= MASK51; r[1] += c;
	c = r[1] >> 51; r[1] &= MASK51; r[2] += c;
	c = r[2] >> 51; r[2] &= MASK51; r[3] += c;
	c = r[3] >> 51; r[3] &= MASK51; r[4] += c;
	c = r[4] >> 51; r[4] &= MASK51; r[0] += c * 19;
	c = r[0] >> 51; r[0] &= MASK51; r[1] += c;
}

static void fe_mul(fe r, const fe a, const fe b) {
	__uint128_t t0, t1, t2, t3, t4;
	uint64_t b1_19 = b[1]*19, b2_19 = b[2]*19, b3_19 = b[3]*19, b4_19 = b[4]*19;

	t0 = (__uint128_t)a[0]*b[0] + (__uint128_t)a[1]*b4_19 + (__uint128_t)a[2]*b3_19 + (__uint128_t)a[3]*b2_19 + (__uint128_t)a[4]*b1_19;
	t1 = (__uint128_t)a[0]*b[1] + (__uint128_t)a[1]*b[0]  + (__uint128_t)a[2]*b4_19 + (__uint128_t)a[3]*b3_19 + (__uint128_t)a[4]*b2_19;
	t2 = (__uint128_t)a[0]*b[2] + (__uint128_t)a[1]*b[1]  + (__uint128_t)a[2]*b[0]  + (__uint128_t)a[3]*b4_19 + (__uint128_t)a[4]*b3_19;
	t3 = (__uint128_t)a[0]*b[3] + (__uint128_t)a[1]*b[2]  + (__uint128_t)a[2]*b[1]  + (__uint128_t)a[3]*b[0]  + (__uint128_t)a[4]*b4_19;
	t4 = (__uint128_t)a[0]*b[4] + (__uint128_t)a[1]*b[3]  + (__uint128_t)a[2]*b[2]  + (__uint128_t)a[3]*b[1]  + (__uint128_t)a[4]*b[0];

	uint64_t c;
	r[0] = (uint64_t)t0 & MASK51; c = (uint64_t)(t0 >> 51);
	t1 += c; r[1] = (uint64_t)t1 & MASK51; c = (uint64_t)(t1 >> 51);
	t2 += c; r[2] = (uint64_t)t2 & MASK51; c = (uint64_t)(t2 >> 51);
	t3 += c; r[3] = (uint64_t)t3 & MASK51; c = (uint64_t)(t3 >> 51);
	t4 += c; r[4] = (uint64_t)t4 & MASK51; c = (uint64_t)(t4 >> 51);
	r[0] += c * 19;
	c = r[0] >> 51; r[0] &= MASK51; r[1] += c;
}

static void fe_sq(fe r, const fe a) {
	uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
	uint64_t a1_2 = a1 * 2, a2_2 = a2 * 2, a3_2 = a3 * 2, a4_2 = a4 * 2;
	uint64_t a1_38 = a1 * 38, a2_38 = a2 * 38, a3_38 = a3 * 38;

	__uint128_t t0 = (__uint128_t)a0*a0   + (__uint128_t)a1_38*a4 + (__uint128_t)a2_38*a3;
	__uint128_t t1 = (__uint128_t)a0*a1_2  + (__uint128_t)a2_38*a4 + (__uint128_t)(a3*19)*a3;
	__uint128_t t2 = (__uint128_t)a0*a2_2  + (__uint128_t)a1*a1    + (__uint128_t)a3_38*a4;
	__uint128_t t3 = (__uint128_t)a0*a3_2  + (__uint128_t)a1_2*a2  + (__uint128_t)(a4*19)*a4;
	__uint128_t t4 = (__uint128_t)a0*a4_2  + (__uint128_t)a1_2*a3  + (__uint128_t)a2*a2;

	uint64_t c;
	r[0] = (uint64_t)t0 & MASK51; c = (uint64_t)(t0 >> 51);
	t1 += c; r[1] = (uint64_t)t1 & MASK51; c = (uint64_t)(t1 >> 51);
	t2 += c; r[2] = (uint64_t)t2 & MASK51; c = (uint64_t)(t2 >> 51);
	t3 += c; r[3] = (uint64_t)t3 & MASK51; c = (uint64_t)(t3 >> 51);
	t4 += c; r[4] = (uint64_t)t4 & MASK51; c = (uint64_t)(t4 >> 51);
	r[0] += c * 19;
	c = r[0] >> 51; r[0] &= MASK51; r[1] += c;
}

static void fe_mul_small(fe r, const fe a, uint64_t s) {
	__uint128_t t;
	uint64_t c;
	t = (__uint128_t)a[0]*s;     r[0] = (uint64_t)t & MASK51; c = (uint64_t)(t >> 51);
	t = (__uint128_t)a[1]*s + c; r[1] = (uint64_t)t & MASK51; c = (uint64_t)(t >> 51);
	t = (__uint128_t)a[2]*s + c; r[2] = (uint64_t)t & MASK51; c = (uint64_t)(t >> 51);
	t = (__uint128_t)a[3]*s + c; r[3] = (uint64_t)t & MASK51; c = (uint64_t)(t >> 51);
	t = (__uint128_t)a[4]*s + c; r[4] = (uint64_t)t & MASK51; c = (uint64_t)(t >> 51);
	r[0] += c * 19;
}

static void fe_tobytes(uint8_t s[32], const fe h_in) {
	fe h;
	fe_copy(h, h_in);
	fe_reduce(h);
	fe_reduce(h);

	uint64_t q = (h[0] + 19) >> 51;
	q = (h[1] + q) >> 51;
	q = (h[2] + q) >> 51;
	q = (h[3] + q) >> 51;
	q = (h[4] + q) >> 51;
	h[0] += 19 * q;
	fe_reduce(h);

	uint64_t buf[4];
	buf[0] = h[0] | (h[1] << 51);
	buf[1] = (h[1] >> 13) | (h[2] << 38);
	buf[2] = (h[2] >> 26) | (h[3] << 25);
	buf[3] = (h[3] >> 39) | (h[4] << 12);
	memcpy(s, buf, 32);
}

static void fe_inv(fe r, const fe z) {
	fe z2, z9, z11, z_5_0, z_10_0, z_20_0, z_40_0, z_50_0, z_100_0, z_200_0, z_250_0, t;
	int i;

	fe_sq(z2, z);
	fe_sq(t, z2); fe_sq(t, t);
	fe_mul(z9, t, z);
	fe_mul(z11, z9, z2);
	fe_sq(t, z11);
	fe_mul(z_5_0, t, z9);

	fe_sq(t, z_5_0);
	for (i = 1; i < 5; i++) fe_sq(t, t);
	fe_mul(z_10_0, t, z_5_0);

	fe_sq(t, z_10_0);
	for (i = 1; i < 10; i++) fe_sq(t, t);
	fe_mul(z_20_0, t, z_10_0);

	fe_sq(t, z_20_0);
	for (i = 1; i < 20; i++) fe_sq(t, t);
	fe_mul(z_40_0, t, z_20_0);

	fe_sq(t, z_40_0);
	for (i = 1; i < 10; i++) fe_sq(t, t);
	fe_mul(z_50_0, t, z_10_0);

	fe_sq(t, z_50_0);
	for (i = 1; i < 50; i++) fe_sq(t, t);
	fe_mul(z_100_0, t, z_50_0);

	fe_sq(t, z_100_0);
	for (i = 1; i < 100; i++) fe_sq(t, t);
	fe_mul(z_200_0, t, z_100_0);

	fe_sq(t, z_200_0);
	for (i = 1; i < 50; i++) fe_sq(t, t);
	fe_mul(z_250_0, t, z_50_0);

	fe_sq(t, z_250_0);
	for (i = 1; i < 5; i++) fe_sq(t, t);
	fe_mul(r, t, z11);
}

/* Montgomery curve arithmetic, base point u=9, a24=121666 */

static void cswap(fe a, fe b, int swap) {
	uint64_t m = -(uint64_t)swap;
	for (int j = 0; j < 5; j++) {
		uint64_t t = m & (a[j] ^ b[j]);
		a[j] ^= t;
		b[j] ^= t;
	}
}

/* [scalar] * base_point(u=9) -> projective (X:Z) */
static void mont_ladder(fe rx, fe rz, const uint8_t scalar[32]) {
	fe x2, z2, x3, z3;
	fe_1(x2); fe_0(z2);
	fe_0(x3); x3[0] = 9; fe_1(z3);

	int swap = 0;
	for (int i = 255; i >= 0; i--) {
		int bit = (scalar[i/8] >> (i%8)) & 1;
		swap ^= bit;
		cswap(x2, x3, swap);
		cswap(z2, z3, swap);
		swap = bit;

		fe A, B, AA, BB, E, C, D, DA, CB, t;
		fe_add(A, x2, z2);
		fe_sq(AA, A);
		fe_sub(B, x2, z2);
		fe_sq(BB, B);
		fe_sub(E, AA, BB);
		fe_add(C, x3, z3);
		fe_sub(D, x3, z3);
		fe_mul(DA, D, A);
		fe_mul(CB, C, B);
		fe_add(t, DA, CB);
		fe_sq(x3, t);
		fe_sub(t, DA, CB);
		fe_sq(t, t);
		fe_mul_small(z3, t, 9);
		fe_mul(x2, AA, BB);
		fe_mul_small(t, E, 121666);
		fe_add(t, t, BB);
		fe_mul(z2, E, t);
	}
	cswap(x2, x3, swap);
	cswap(z2, z3, swap);
	fe_copy(rx, x2);
	fe_copy(rz, z2);
}

/* Differential addition: rx = cx + step, where px = cx - step */
static void mont_dadd(fe rx, fe rz, const fe cx, const fe cz, const fe px, const fe pz, const fe sxpz, const fe sxmz) {
	fe U, V, sum, diff;
	fe_sub(U, cx, cz);
	fe_mul(U, U, sxpz);
	fe_add(V, cx, cz);
	fe_mul(V, V, sxmz);
	fe_add(sum, U, V);
	fe_sub(diff, U, V);
	fe_sq(sum, sum);
	fe_sq(diff, diff);
	fe_mul(rx, pz, sum);
	fe_mul(rz, px, diff);
}

#ifndef BATCH
#define BATCH 1024
#endif

/* Key clamping and base64 */

static void clamp(uint8_t k[32]) {
	k[0]  &= 248;
	k[31] &= 127;
	k[31] |= 64;
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64enc(char *out, const uint8_t *in, int len) {
	int i, j = 0;
	for (i = 0; i + 2 < len; i += 3) {
		out[j++] = B64[in[i] >> 2];
		out[j++] = B64[((in[i]&3)<<4)|(in[i+1]>>4)];
		out[j++] = B64[((in[i+1]&15)<<2)|(in[i+2]>>6)];
		out[j++] = B64[in[i+2] & 63];
	}
	if (i < len) {
		out[j++] = B64[in[i] >> 2];
		if (i+1 < len) {
			out[j++] = B64[((in[i]&3)<<4)|(in[i+1]>>4)];
			out[j++] = B64[(in[i+1]&15)<<2];
		} else {
			out[j++] = B64[(in[i]&3)<<4];
			out[j++] = '=';
		}
		out[j++] = '=';
	}
	out[j] = '\0';
}

static int b64val(int c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

/* Prefix matching */

typedef struct {
	uint64_t target, mask;
	int len;
	int ndigits;
	int digit_shift[10];
} prefix_t;

static int prefix_init(prefix_t *p, const char *s) {
	int len = strlen(s);
	if (len < 1 || len > 10) {
		fprintf(stderr, "Prefix must be 1-10 chars\n");
		return -1;
	}
	for (int i = 0; i < len; i++) {
		if (s[i] != '-' && s[i] != '?' && b64val(s[i]) < 0) {
			fprintf(stderr, "Invalid base64 char: '%c'\n", s[i]);
			return -1;
		}
	}
	uint64_t bits = 0, mask = 0;
	p->ndigits = 0;
	for (int i = 0; i < len; i++) {
		if (s[i] == '-') {
			bits = (bits << 6) | 62;
			mask = (mask << 6) | 0x3E;
		} else if (s[i] == '?') {
			bits = (bits << 6);
			mask = (mask << 6);
			p->digit_shift[p->ndigits++] = 64 - (i + 1) * 6;
		} else {
			bits = (bits << 6) | b64val(s[i]);
			mask = (mask << 6) | 0x3F;
		}
	}
	int nbits = len * 6;
	bits <<= (64 - nbits);
	mask <<= (64 - nbits);
	p->target = bits;
	p->mask = mask;
	p->len = len;
	return 0;
}

static inline int prefix_match(const prefix_t *p, uint64_t v) {
	if ((v & p->mask) != p->target) return 0;
	for (int i = 0; i < p->ndigits; i++) {
		unsigned d = (v >> p->digit_shift[i]) & 0x3F;
		if (d - 52 > 9) return 0;
	}
	return 1;
}

/* Worker thread */

typedef struct {
	prefix_t pm;
	volatile int *remaining;
	pthread_mutex_t *mu;
	uint64_t count;
} worker_t;

static void scalar_add8n(uint8_t out[32], const uint8_t base[32], uint64_t n) {
	memcpy(out, base, 32);
	uint64_t *w = (uint64_t *)out;
	uint64_t add = n * 8;
	uint64_t v = w[0] + add;
	uint64_t c = v < w[0];
	w[0] = v;
	v = w[1] + c; c = v < w[1];
	w[1] = v;
	v = w[2] + c; c = v < w[2];
	w[2] = v;
	w[3] = (w[3] + c) | (1ULL << 62);
	w[3] &= (1ULL << 63) - 1;
}

static void *worker(void *arg) {
	worker_t *w = arg;
	uint8_t start_priv[32] __attribute__((aligned(8)));
	fe xs[BATCH], zs[BATCH], acc[BATCH];

	FILE *f = fopen("/dev/urandom", "rb");
	if (!f) { perror("/dev/urandom"); return NULL; }
	if (fread(start_priv, 1, 32, f) != 32) { fclose(f); return NULL; }
	fclose(f);
	clamp(start_priv);

	mont_ladder(xs[0], zs[0], start_priv);

	uint8_t priv1[32];
	scalar_add8n(priv1, start_priv, 1);
	mont_ladder(xs[1], zs[1], priv1);

	/* Precompute step constants for dadd */
	fe step_x, step_z, step_xpz, step_xmz;
	{
		uint8_t eight[32] = {8};
		mont_ladder(step_x, step_z, eight);
	}
	fe_add(step_xpz, step_x, step_z);
	fe_sub(step_xmz, step_x, step_z);

	uint64_t count = 0;

	while (*w->remaining > 0) {
		for (int i = 1; i < BATCH - 1; i++)
			mont_dadd(xs[i+1], zs[i+1], xs[i], zs[i],
			          xs[i-1], zs[i-1], step_xpz, step_xmz);

		/* Batch invert Z's and check prefix */
		fe_copy(acc[0], zs[0]);
		for (int i = 1; i < BATCH; i++)
			fe_mul(acc[i], acc[i-1], zs[i]);

		fe inv, u;
		fe_inv(inv, acc[BATCH-1]);

		for (int i = BATCH - 1; i >= 0; i--) {
			if (i > 0) {
				fe tmp;
				fe_mul(tmp, inv, acc[i-1]);
				fe_mul(inv, inv, zs[i]);
				fe_mul(u, xs[i], tmp);
			} else {
				fe_mul(u, xs[0], inv);
			}

			uint64_t v = __builtin_bswap64(u[0] | (u[1] << 51));
			if (!prefix_match(&w->pm, v)) continue;

			uint8_t pub[32], priv[32];
			fe_tobytes(pub, u);
			scalar_add8n(priv, start_priv, count + i);
			char pub_b64[45], priv_b64[45];
			b64enc(pub_b64, pub, 32);
			b64enc(priv_b64, priv, 32);
			pthread_mutex_lock(w->mu);
			if (*w->remaining > 0) {
				printf("%s %s\n", pub_b64, priv_b64);
				(*w->remaining)--;
			}
			pthread_mutex_unlock(w->mu);
		}

		mont_dadd(xs[0], zs[0], xs[BATCH-1], zs[BATCH-1],
		          xs[BATCH-2], zs[BATCH-2], step_xpz, step_xmz);
		mont_dadd(xs[1], zs[1], xs[0], zs[0],
		          xs[BATCH-1], zs[BATCH-1], step_xpz, step_xmz);
		count += BATCH;
	}
	w->count = count;
	return NULL;
}

/* Main */

int main(int argc, char **argv) {
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "wg-vanity %s\n"
			"Usage: %s <prefix> [count]\n"
			"  -  matches + or /\n"
			"  ?  matches any digit 0-9\n", VERSION, argv[0]);
		return 1;
	}

	prefix_t pm;
	if (prefix_init(&pm, argv[1]) != 0) return 1;

	int want = 1;
	if (argc == 3) {
		want = atoi(argv[2]);
		if (want < 1) want = 1;
	}

	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1) ncpu = 1;

	fprintf(stderr, "Searching '%s' (%d bits) with %d threads...\n",
		argv[1], pm.len * 6, ncpu);

	volatile int remaining = want;
	pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
	worker_t *ws = calloc(ncpu, sizeof *ws);
	pthread_t *ts = calloc(ncpu, sizeof *ts);

	struct timespec t0;
	clock_gettime(CLOCK_MONOTONIC, &t0);

	for (int i = 0; i < ncpu; i++) {
		ws[i].pm = pm;
		ws[i].remaining = &remaining;
		ws[i].mu = &mu;
		pthread_create(&ts[i], NULL, worker, &ws[i]);
	}
	for (int i = 0; i < ncpu; i++)
		pthread_join(ts[i], NULL);

	struct timespec t1;
	clock_gettime(CLOCK_MONOTONIC, &t1);
	double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

	uint64_t total = 0;
	for (int i = 0; i < ncpu; i++)
		total += ws[i].count;

	fprintf(stderr, "Found %d in %.1fs (%llu keys, %.0f keys/s)\n",
		want, elapsed, (unsigned long long)total, total / elapsed);

	free(ws);
	free(ts);
	return 0;
}

