/* Automated version of the manual test plan (T1..T25).
 * Build/run with tests/run_tests.sh (Linux/WSL, gcc).  Test-side code only:
 * time() is replaced by a fake clock and SSHA calls are counted via the
 * linker's --wrap option, so the product source needs no test hooks. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include "user.h"
#include "hash.h"

static time_t fake_now = 1700000000;
time_t __wrap_time(time_t* t) { fake_now += 7; if (t) *t = fake_now; return fake_now; }
unsigned char* __real_SSHA(const unsigned char*, size_t);
static int ssha_calls = 0;
unsigned char* __wrap_SSHA(const unsigned char* m, size_t n) { ssha_calls++; return __real_SSHA(m, n); }

#define N 5
static const char* NAMES[N] = { "rob", "hanif", "gahyun", "matt", "sumita" };
static const char* cur_id; static int cur_ok; static char cur_msg[256]; static int total_fail;
static void T(const char* id, const char* title) { cur_id = id; cur_ok = 1; cur_msg[0] = 0; printf("%-4s %-52s ", id, title); fflush(stdout); }
#define EXPECT(c, ...) do { if (!(c) && cur_ok) { cur_ok = 0; snprintf(cur_msg, sizeof cur_msg, __VA_ARGS__); } } while (0)
static void END(void) { if (cur_ok) printf("PASS\n"); else { printf("FAIL  (%s)\n", cur_msg); total_fail++; } fflush(stdout); }

static struct User* build(int n) { struct User* h = NULL; for (int i = 0; i < n; i++) h = add(h, (char*)NAMES[i]); return h; }
static struct User* nth(struct User* h, int k) { while (h && k--) h = h->next; return h; }
static int count(struct User* h) { int c = 0; while (h && c < 1000) { c++; h = h->next; } return c; }
static struct Digest digest_of(const struct User* u) {
    unsigned char* r = __real_SSHA((const unsigned char*)u, STRUCT_SIZE);
    struct Digest d = { r[0], r[1], r[2], r[3], r[4] }; free(r); return d;
}

static char cap[1 << 16];
static void capture(void (*fn)(struct User*), struct User* h) {
    fflush(stdout); int saved = dup(1);
    int fd = open("cap.tmp", O_CREAT | O_TRUNC | O_WRONLY, 0600); dup2(fd, 1); close(fd);
    fn(h); fflush(stdout); dup2(saved, 1); close(saved);
    FILE* f = fopen("cap.tmp", "rb"); size_t n = f ? fread(cap, 1, sizeof cap - 1, f) : 0; cap[n] = 0; if (f) fclose(f);
}
static int count_str(const char* s) { int c = 0; const char* p = cap; while ((p = strstr(p, s))) { c++; p += strlen(s); } return c; }
static int banner(void) { return strstr(cap, "All blocks have been verified") != NULL; }
static int failed_user(const char** at) {
    const char* p = cap;
    while ((p = strstr(p, "User "))) { int k; char w[16];
        if (sscanf(p, "User %d %15s", &k, w) == 2 && strcmp(w, "failed") == 0) { if (at) *at = p; return k; }
        p += 5; }
    return 0;
}
static int parse_all(const char* key, struct Digest* out, int max) {
    int c = 0; const char* p = cap;
    while (c < max && (p = strstr(p, key))) { p += strlen(key); int a, b, cc, d, e;
        if (sscanf(p, " %d %d %d %d %d", &a, &b, &cc, &d, &e) != 5) break;
        out[c].hash0 = a; out[c].hash1 = b; out[c].hash2 = cc; out[c].hash3 = d; out[c].hash4 = e; c++; }
    return c;
}
static int deq(struct Digest a, struct Digest b) { return digest_equal(a, b); }

/* control: an untouched fixture must verify cleanly before we tamper with it */
static void control(struct User* h) { capture(verify, h); EXPECT(failed_user(NULL) == 0 && banner(), "control: untouched log did not verify cleanly"); }
static void expect_fail_at(struct User* h, int want, const char* what) {
    const char* at = NULL; capture(verify, h); int k = failed_user(&at);
    EXPECT(k == want, "%s: expected failure at User %d, got %d", what, want, k);
    EXPECT(!banner(), "%s: success banner printed despite tampering", what);
    if (at && k) { const char* u = strstr(at, "Username:"); char nm[64] = ""; if (u) sscanf(u, "Username: %63s", nm);
        struct User* exp = nth(h, k - 1); EXPECT(exp && strcmp(nm, exp->Username) == 0, "%s: failure shows '%s', expected '%s'", what, nm, exp ? exp->Username : "?"); }
}

static void t1(void) { T("T1", "usernames stored"); struct User* h = build(N);
    for (int k = 0; k < N; k++) { struct User* u = nth(h, k); EXPECT(u && strcmp(u->Username, NAMES[N - 1 - k]) == 0, "entry %d name wrong", k); } END(); }
static void t2(void) { T("T2", "timestamps inside add window, increasing, tm matches"); struct User* h = NULL; time_t lo[N], hi[N];
    for (int i = 0; i < N; i++) { lo[i] = fake_now; h = add(h, (char*)NAMES[i]); hi[i] = fake_now; }
    for (int i = 0; i < N; i++) { struct User* u = nth(h, N - 1 - i); EXPECT(u->loginTime > lo[i] && u->loginTime <= hi[i], "entry %d time outside add window", i);
        struct tm* l = localtime(&u->loginTime); EXPECT(l->tm_sec == u->localLoginTime.tm_sec && l->tm_min == u->localLoginTime.tm_min && l->tm_hour == u->localLoginTime.tm_hour, "tm differs from loginTime");
        if (i) EXPECT(u->loginTime > nth(h, N - i)->loginTime, "timestamps not increasing"); } END(); }
static void t3(void) { T("T3", "add makes exactly one entry, older entries intact"); struct User* h = NULL; unsigned char* snap = malloc(STRUCT_SIZE);
    for (int i = 0; i < N; i++) { if (h) memcpy(snap, h, STRUCT_SIZE); struct User* o = h; h = add(h, (char*)NAMES[i]);
        EXPECT(count(h) == i + 1, "after add %d count is %d", i + 1, count(h)); if (o) EXPECT(memcmp(snap, o, STRUCT_SIZE) == 0, "older entry modified by add"); }
    free(snap); END(); }
static void t4(void) { T("T4", "new entry is head and links to previous head"); struct User* h = NULL;
    for (int i = 0; i < N; i++) { struct User* o = h; h = add(h, (char*)NAMES[i]); EXPECT(h && strcmp(h->Username, NAMES[i]) == 0, "add %d did not return new entry", i); EXPECT(h && h->next == o, "add %d: next != previous head", i); } END(); }
static void t5(void) { T("T5", "traversal newest->oldest, terminates at NULL"); struct User* h = build(N); int c = 0; struct User* p = h;
    while (p && c <= N + 1) { EXPECT(c >= N || strcmp(p->Username, NAMES[N - 1 - c]) == 0, "order wrong at %d", c); p = p->next; c++; }
    EXPECT(c == N && p == NULL, "walk visited %d nodes", c); END(); }
static void t6(void) { T("T6", "printLog: name, time, hash per entry, newest first"); struct User* h = build(N); capture(printLog, h);
    char* copy = strdup(cap); char* sv; int k = 0;
    for (char* ln = strtok_r(copy, "\n", &sv); ln; ln = strtok_r(NULL, "\n", &sv)) { if (strncmp(ln, "Username:", 9)) continue; struct User* u = nth(h, k); if (!u) break;
        char ts[64], hs[64]; snprintf(ts, sizeof ts, "%02d/%02d/%04d %02d:%02d:%02d", u->localLoginTime.tm_mon + 1, u->localLoginTime.tm_mday, u->localLoginTime.tm_year + 1900, u->localLoginTime.tm_hour, u->localLoginTime.tm_min, u->localLoginTime.tm_sec);
        snprintf(hs, sizeof hs, "Hash: %d %d %d %d %d", u->hash.hash0, u->hash.hash1, u->hash.hash2, u->hash.hash3, u->hash.hash4);
        EXPECT(k < N && strstr(ln, NAMES[N - 1 - k]), "line %d name", k); EXPECT(strstr(ln, ts), "line %d time", k); EXPECT(strstr(ln, hs), "line %d hash", k); k++; }
    EXPECT(k == N, "%d entry lines, expected %d", k, N); free(copy); END(); }
static void t7(void) { T("T7", "oldest entry holds fixed, non-zero seed hash"); struct User* a = build(N); struct User* b = build(N);
    struct Digest z = { 0, 0, 0, 0, 0 }; EXPECT(deq(nth(a, N - 1)->hash, nth(b, N - 1)->hash), "seed differs between builds"); EXPECT(!deq(nth(a, N - 1)->hash, z), "seed is all zeros"); END(); }
static void t8(void) { T("T8", "stored hash == digest of predecessor entry"); struct User* h = build(N);
    for (int k = 0; k < N - 1; k++) EXPECT(deq(nth(h, k)->hash, digest_of(nth(h, k + 1))), "entry %d hash != digest of entry %d", k, k + 1); END(); }
static void t9(void) { T("T9", "SSHA call counts: add 0/1, verify n-1"); ssha_calls = 0; struct User* h = add(NULL, "rob"); EXPECT(ssha_calls == 0, "first add made %d SSHA calls", ssha_calls);
    for (int i = 1; i < N; i++) { ssha_calls = 0; h = add(h, (char*)NAMES[i]); EXPECT(ssha_calls == 1, "add %d made %d SSHA calls", i + 1, ssha_calls); }
    ssha_calls = 0; capture(verify, h); EXPECT(ssha_calls == N - 1, "verify made %d SSHA calls, expected %d", ssha_calls, N - 1); END(); }
static void t10(void) { T("T10", "digest repeatable (same node, and byte copy)"); struct User* h = build(N); struct User* n = nth(h, 2);
    struct Digest a = digest_of(n), b = digest_of(n), c = digest_of(n); EXPECT(deq(a, b) && deq(b, c), "repeat digests differ");
    struct User* cp = malloc(STRUCT_SIZE); memcpy(cp, n, STRUCT_SIZE); EXPECT(deq(a, digest_of(cp)), "byte copy digest differs"); free(cp); END(); }
static struct User* copy_of(struct User* n) { struct User* c = malloc(STRUCT_SIZE); memcpy(c, n, STRUCT_SIZE); return c; }
static void t11(void) { T("T11", "digest covers username (every char position)"); struct User* h = build(N); struct User* n = nth(h, 2); struct Digest d = digest_of(n);
    for (size_t i = 0; i < strlen(n->Username); i++) { struct User* c = copy_of(n); c->Username[i] ^= 1; EXPECT(!deq(d, digest_of(c)), "char %zu change not reflected", i); free(c); } END(); }
static void t12(void) { T("T12", "digest covers loginTime and localLoginTime"); struct User* h = build(N); struct User* n = nth(h, 2); struct Digest d = digest_of(n);
    struct User* c = copy_of(n); c->loginTime += 1; EXPECT(!deq(d, digest_of(c)), "raw loginTime change not reflected"); free(c);
    c = copy_of(n); c->localLoginTime.tm_sec += 1; EXPECT(!deq(d, digest_of(c)), "tm_sec change not reflected"); free(c); END(); }
static void t13(void) { T("T13", "digest covers stored hash (each of 5 bytes)"); struct User* h = build(N); struct User* n = nth(h, 2); struct Digest d = digest_of(n);
    for (int b = 0; b < 5; b++) { struct User* c = copy_of(n); unsigned char* p = &c->hash.hash0; p[b] ^= 1; EXPECT(!deq(d, digest_of(c)), "hash byte %d change not reflected", b); free(c); } END(); }

static void t14(void) { T("T14", "verify walk: starts at head, n-1 comparisons, ends at oldest"); struct User* h = build(N); capture(verify, h);
    EXPECT(strstr(cap, "User 1, impossible to verify"), "no 'User 1, impossible to verify'"); EXPECT(count_str(" passed\n") == N - 1, "%d comparisons reported, expected %d", count_str(" passed\n"), N - 1);
    char want[64]; snprintf(want, sizeof want, "User %d, nothing to verify", N); EXPECT(strstr(cap, want), "final line should be '%s'", want); END(); }
static void t15(void) { T("T15", "reported saved/calculated hashes match independent values"); struct User* h = build(N); capture(verify, h);
    struct Digest sv[N + 1], cl[N + 1]; int ns = parse_all("Saved Hash:", sv, N + 1), nc = parse_all("Calculated Hash:", cl, N + 1);
    EXPECT(nc == N - 1 && ns == N, "found %d saved / %d calculated hashes", ns, nc);
    for (int k = 0; k < nc && k < ns; k++) { EXPECT(deq(sv[k], nth(h, k)->hash), "saved hash %d wrong", k); EXPECT(deq(cl[k], digest_of(nth(h, k + 1))), "calculated hash %d != independent digest of entry %d", k, k + 1); } END(); }
static void t16(void) { T("T16", "clean log: all pass, no failure, success banner"); struct User* h = build(N); capture(verify, h);
    EXPECT(failed_user(NULL) == 0, "clean log reported failure at User %d", failed_user(NULL)); EXPECT(count_str(" passed\n") == N - 1, "%d passes", count_str(" passed\n")); EXPECT(banner(), "no success banner"); END(); }
static void t17(void) { T("T17", "corrupt middle entry: passes before, fails at it, no banner"); struct User* h = build(N); control(h); nth(h, 2)->Username[0] ^= 1;
    capture(verify, h); EXPECT(strstr(cap, "User 2 passed"), "User 2 should still pass"); expect_fail_at(h, 3, "middle"); END(); }
static void t18(void) { T("T18", "verify leaves log unchanged"); struct User* h = build(N); unsigned char* snap = malloc(N * STRUCT_SIZE); for (int k = 0; k < N; k++) memcpy(snap + k * STRUCT_SIZE, nth(h, k), STRUCT_SIZE);
    struct User* ph[N]; for (int k = 0; k < N; k++) ph[k] = nth(h, k); capture(verify, h);
    EXPECT(count(h) == N, "node count changed"); for (int k = 0; k < N; k++) { EXPECT(nth(h, k) == ph[k], "link %d changed", k); EXPECT(memcmp(snap + k * STRUCT_SIZE, ph[k], STRUCT_SIZE) == 0, "node %d bytes changed", k); } free(snap); END(); }
static void t19(void) { T("T19", "modified username detected (each non-head entry)"); for (int j = 1; j < N; j++) { struct User* h = build(N); control(h); nth(h, j)->Username[0] ^= 1; expect_fail_at(h, j + 1, "username"); } END(); }
static void t20(void) { T("T20", "modified timestamp detected (raw and tm, each entry)"); for (int j = 1; j < N; j++) {
        struct User* h = build(N); control(h); nth(h, j)->loginTime += 3; expect_fail_at(h, j + 1, "loginTime");
        h = build(N); control(h); nth(h, j)->localLoginTime.tm_sec += 3; expect_fail_at(h, j + 1, "tm_sec"); } END(); }
static void t21(void) { T("T21", "modified stored hash detected (middle, oldest, head)"); struct User* h = build(N); control(h); nth(h, 2)->hash.hash0 ^= 1; expect_fail_at(h, 3, "middle hash");
    h = build(N); control(h); nth(h, N - 1)->hash.hash0 ^= 1; expect_fail_at(h, N, "oldest hash"); h = build(N); control(h); nth(h, 0)->hash.hash0 ^= 1; expect_fail_at(h, 2, "head hash"); END(); }
static void t22(void) { T("T22", "removed entry detected"); struct User* h = build(N); control(h); nth(h, 1)->next = nth(h, 3); const char* at; capture(verify, h);
    int k = failed_user(&at); EXPECT(k == 2 || k == 3, "removal: expected failure at User 2 or 3, got %d", k); EXPECT(!banner(), "banner printed after removal"); END(); }
static void t23(void) { T("T23", "inserted (forged) entry detected"); struct User* h = build(N); control(h); struct User* f = calloc(1, STRUCT_SIZE); struct User* e2 = nth(h, 2);
    strcpy(f->Username, "mallory"); f->loginTime = e2->loginTime; f->localLoginTime = e2->localLoginTime; f->hash = e2->hash; f->next = e2; nth(h, 1)->next = f;
    capture(verify, h); int k = failed_user(NULL); EXPECT(k == 2 || k == 3, "insertion: expected failure at User 2 or 3, got %d", k); EXPECT(!banner(), "banner printed after insertion"); END(); }
static void t24(void) { T("T24", "reordered entries detected"); struct User* h = build(N); control(h); struct User *e1 = nth(h, 1), *e2 = nth(h, 2), *e3 = nth(h, 3);
    h->next = e2; e2->next = e1; e1->next = e3; capture(verify, h); int k = failed_user(NULL); EXPECT(k == 2 || k == 3, "swap: expected failure at User 2 or 3, got %d", k); EXPECT(!banner(), "banner printed after swap"); END(); }

static void ref_ssha(const unsigned char* m, size_t n, unsigned char o[5]) { /* straight from the diagram */
    unsigned char A = 56, B = 99, C = 102, D = 67, E = 76;
    for (size_t i = 0; i < n; i++) { unsigned char a = A, b = B, c = C, d = D, e = E;
        A = e; B = a; C = (unsigned char)((a >> 2) + e); D = (unsigned char)((a >> 2) ^ (b >> 1)); E = (unsigned char)(m[i] + (b >> 1) + ((b & c) | (d & c))); }
    o[0] = A; o[1] = B; o[2] = C; o[3] = D; o[4] = E; }
static void t25(void) { T("T25", "SSHA matches the diagram (reference implementation)");
    const char* in[] = { "", "A", "abc", "The quick brown fox", "0123456789012345678901234567890123456789" };
    for (int i = 0; i < 5; i++) { unsigned char r[5]; ref_ssha((const unsigned char*)in[i], strlen(in[i]), r); unsigned char* g = __real_SSHA((const unsigned char*)in[i], strlen(in[i]));
        EXPECT(memcmp(r, g, 5) == 0, "input \"%.12s\": got %d %d %d %d %d, diagram gives %d %d %d %d %d", in[i], g[0], g[1], g[2], g[3], g[4], r[0], r[1], r[2], r[3], r[4]); free(g); } END(); }

int main(void) {
    alarm(120);
    t1(); t2(); t3(); t4(); t5(); t6(); t7(); t8(); t9(); t10(); t11(); t12(); t13();
    t14(); t15(); t16(); t17(); t18(); t19(); t20(); t21(); t22(); t23(); t24(); t25();
    printf("\n%d test(s) failed\n", total_fail); return total_fail ? 1 : 0;
}
