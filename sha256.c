/** 
 * @file hash.c
 * @author jclawlor
 * Helper file for the hash program containing the functions for SHA256 style hashing
*/

#include "sha256.h"
#include "sha256constants.h"
#include <stdlib.h>
#include <stdio.h>


word rotate(word val, int bits)
{
    return (val >> bits | (val << ((sizeof(word) * BBITS) - bits)));
}

word Sigma0(word a)
{
    return (rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22));
}

word Sigma1(word e)
{
    return (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25));
}

word ChFunction(word e, word f, word g)
{
    return ((e & f) ^ (~e & g));
}

word MaFunction(word a, word b, word c)
{
    return ((a & b) ^ (a & c) ^ (b & c));
}

void extendMessage(byte const pending[BLOCK_SIZE], word w[BLOCK_SIZE])
{
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        if (i < 16)
        {
            w[i] = (pending[i * 4] << 24) | (pending[i * 4 + 1] << 16) | (pending[i * 4 + 2] << 8) |
                   pending[i * 4 + 3];
        }
        else
        {
            w[i] = (w[i - 16] + w[i - 7] + (rotate(w[i - 15], 7) ^ rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)) +
                    (rotate(w[i - 2], 17) ^ rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)));
        }
    }
}

void compression(SHAState *state)
{

    word w[BLOCK_SIZE] = {};
    extendMessage(state->pending, w);
    word A = state->h[0];
    word B = state->h[1];
    word C = state->h[2];
    word D = state->h[3];
    word E = state->h[4];
    word F = state->h[5];
    word G = state->h[6];
    word H = state->h[7];

    int originalA = A;
    int originalB = B;
    int originalC = C;
    int originalD = D;
    int originalE = E;
    int originalF = F;
    int originalG = G;
    int originalH = H;

    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        int level1 = ChFunction(E, F, G) + constant_k[i] + w[i] + H;
        int level2 = level1 + Sigma1(E);
        int level3 = level2 + D;
        int level4 = level2 + MaFunction(A, B, C);
        int level5 = level4 + Sigma0(A);

        H = G;
        G = F;
        F = E;
        E = level3;
        D = C;
        C = B;
        B = A;
        A = level5;
    }

    A += originalA;
    B += originalB;
    C += originalC;
    D += originalD;
    E += originalE;
    F += originalF;
    G += originalG;
    H += originalH;

    state->h[0] = A;
    state->h[1] = B;
    state->h[2] = C;
    state->h[3] = D;
    state->h[4] = E;
    state->h[5] = F;
    state->h[6] = G;
    state->h[7] = H;
}

SHAState *makeState()
{
    SHAState *state = (SHAState *)malloc(sizeof(SHAState));
    for (int i = 0; i < HASH_WORDS; i++)
    {
        state->h[i] = initial_h[i];
    }

    state->pcount = 0;
    state->input = 0;
    return state;
}

void freeState(SHAState *state)
{
    free(state);
}

void update(SHAState *state, const byte data[], int len)
{
    state->pcount = 0;
    int n = 0;
    for (int i = 0; i < len; i++)
    {
        if (state->pcount == BLOCK_SIZE)
        {
            compression(state);
            state->pcount = 0;
        }

        state->pending[state->pcount++] = data[n++];
        state->input++;
    }

    if (state->pcount == BLOCK_SIZE)
    {
        compression(state);
        state->pcount = 0;
    }
}

void digest(SHAState *state, word hash[HASH_WORDS])
{
    word64 length = state->input * BBITS;
    state->pending[state->pcount++] = 0x80;
    if (state->pcount > BLOCK_SIZE - BBITS)
    {
        while (state->pcount < BLOCK_SIZE)
        {
            state->pending[state->pcount++] = 0x00;
        }
        compression(state);
        state->pcount = 0;
        while (state->pcount < BLOCK_SIZE - BBITS)
        {
            state->pending[state->pcount++] = 0x00;
        }
        state->pending[56] = length >> 56;
        state->pending[57] = length >> 48;
        state->pending[58] = length >> 40;
        state->pending[59] = length >> 32;
        state->pending[60] = length >> 24;
        state->pending[61] = length >> 16;
        state->pending[62] = length >> 8;
        state->pending[63] = length;

        compression(state);
    }
    else {
        while (state->pcount < BLOCK_SIZE - BBITS) {
          state->pending[state->pcount++] = 0x00;
        }
        state->pending[56] = length >> 56;
        state->pending[57] = length >> 48;
        state->pending[58] = length >> 40;
        state->pending[59] = length >> 32;
        state->pending[60] = length >> 24;
        state->pending[61] = length >> 16;
        state->pending[62] = length >> 8;
        state->pending[63] = length;

        compression(state);
    }
    
    for (int i = 0; i < HASH_WORDS; i++) {
        hash[i] = state->h[i];
    }
}
