/* Based on the public domain implementation in
* crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
* by Ronny Van Keer
* and the public domain "TweetFips202" implementation
* from https://twitter.com/tweetfips202
* by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "kyber_all.h"
#include "inttypes.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <unistd.h>



/* Precomputed constants for the forward NTT and inverse NTT.
* Computed using Pari/GP as follows:
*
brv=[0,128,64,192,32,160,96,224,16,144,80,208,48,176,112,240, \
8,136,72,200,40,168,104,232,24,152,88,216,56,184,120,248, \
4,132,68,196,36,164,100,228,20,148,84,212,52,180,116,244, \
12,140,76,204,44,172,108,236,28,156,92,220,60,188,124,252, \
2,130,66,194,34,162,98,226,18,146,82,210,50,178,114,242, \
10,138,74,202,42,170,106,234,26,154,90,218,58,186,122,250, \
6,134,70,198,38,166,102,230,22,150,86,214,54,182,118,246, \
14,142,78,206,46,174,110,238,30,158,94,222,62,190,126,254, \
1,129,65,193,33,161,97,225,17,145,81,209,49,177,113,241, \
9,137,73,201,41,169,105,233,25,153,89,217,57,185,121,249, \
5,133,69,197,37,165,101,229,21,149,85,213,53,181,117,245, \
13,141,77,205,45,173,109,237,29,157,93,221,61,189,125,253, \
3,131,67,195,35,163,99,227,19,147,83,211,51,179,115,243, \
11,139,75,203,43,171,107,235,27,155,91,219,59,187,123,251, \
7,135,71,199,39,167,103,231,23,151,87,215,55,183,119,247, \
15,143,79,207,47,175,111,239,31,159,95,223,63,191,127,255];

q = 7681;
n = 256;
mont = Mod(2^18,q);

g=0; for(i=2,q-1,if(znorder(Mod(i,q)) == 2*n, g=Mod(i,q); break))

zetas = lift(vector(n, i, g^(brv[i])*mont))
omegas_inv_bitrev_montgomery = lift(vector(n/2, i, (g^2)^(-brv[2*(i-1)+1])*mont))
psis_inv_montgomery = lift(vector(n, i, g^(-(i-1))/n*mont))

*/

const uint16_t zetas[KYBER_N] = {
	990, 7427, 2634, 6819, 578, 3281, 2143, 1095, 484, 6362, 3336, 5382, 6086, 3823, 877, 5656,
	3583, 7010, 6414, 263, 1285, 291, 7143, 7338, 1581, 5134, 5184, 5932, 4042, 5775, 2468, 3,
	606, 729, 5383, 962, 3240, 7548, 5129, 7653, 5929, 4965, 2461, 641, 1584, 2666, 1142, 157,
	7407, 5222, 5602, 5142, 6140, 5485, 4931, 1559, 2085, 5284, 2056, 3538, 7269, 3535, 7190, 1957,
	3465, 6792, 1538, 4664, 2023, 7643, 3660, 7673, 1694, 6905, 3995, 3475, 5939, 1859, 6910, 4434,
	1019, 1492, 7087, 4761, 657, 4859, 5798, 2640, 1693, 2607, 2782, 5400, 6466, 1010, 957, 3851,
	2121, 6392, 7319, 3367, 3659, 3375, 6430, 7583, 1549, 5856, 4773, 6084, 5544, 1650, 3997, 4390,
	6722, 2915, 4245, 2635, 6128, 7676, 5737, 1616, 3457, 3132, 7196, 4702, 6239, 851, 2122, 3009,
	7613, 7295, 2007, 323, 5112, 3716, 2289, 6442, 6965, 2713, 7126, 3401, 963, 6596, 607, 5027,
	7078, 4484, 5937, 944, 2860, 2680, 5049, 1777, 5850, 3387, 6487, 6777, 4812, 4724, 7077, 186,
	6848, 6793, 3463, 5877, 1174, 7116, 3077, 5945, 6591, 590, 6643, 1337, 6036, 3991, 1675, 2053,
	6055, 1162, 1679, 3883, 4311, 2106, 6163, 4486, 6374, 5006, 4576, 4288, 5180, 4102, 282, 6119,
	7443, 6330, 3184, 4971, 2530, 5325, 4171, 7185, 5175, 5655, 1898, 382, 7211, 43, 5965, 6073,
	1730, 332, 1577, 3304, 2329, 1699, 6150, 2379, 5113, 333, 3502, 4517, 1480, 1172, 5567, 651,
	925, 4573, 599, 1367, 4109, 1863, 6929, 1605, 3866, 2065, 4048, 839, 5764, 2447, 2022, 3345,
	1990, 4067, 2036, 2069, 3567, 7371, 2368, 339, 6947, 2159, 654, 7327, 2768, 6676, 987, 2214 };

const uint16_t omegas_inv_bitrev_montgomery[KYBER_N / 2] = {
	990, 254, 862, 5047, 6586, 5538, 4400, 7103, 2025, 6804, 3858, 1595, 2299, 4345, 1319, 7197,
	7678, 5213, 1906, 3639, 1749, 2497, 2547, 6100, 343, 538, 7390, 6396, 7418, 1267, 671, 4098,
	5724, 491, 4146, 412, 4143, 5625, 2397, 5596, 6122, 2750, 2196, 1541, 2539, 2079, 2459, 274,
	7524, 6539, 5015, 6097, 7040, 5220, 2716, 1752, 28, 2552, 133, 4441, 6719, 2298, 6952, 7075,
	4672, 5559, 6830, 1442, 2979, 485, 4549, 4224, 6065, 1944, 5, 1553, 5046, 3436, 4766, 959,
	3291, 3684, 6031, 2137, 1597, 2908, 1825, 6132, 98, 1251, 4306, 4022, 4314, 362, 1289, 5560,
	3830, 6724, 6671, 1215, 2281, 4899, 5074, 5988, 5041, 1883, 2822, 7024, 2920, 594, 6189, 6662,
	3247, 771, 5822, 1742, 4206, 3686, 776, 5987, 8, 4021, 38, 5658, 3017, 6143, 889, 4216 };

const uint16_t psis_inv_montgomery[KYBER_N] = {
	1024, 4972, 5779, 6907, 4943, 4168,  315, 5580,   90,  497, 1123,  142, 4710, 5527, 2443, 4871,
	698, 2489, 2394, 4003,  684, 2241, 2390, 7224, 5072, 2064, 4741, 1687, 6841,  482, 7441, 1235,
	2126, 4742, 2802, 5744, 6287, 4933,  699, 3604, 1297, 2127, 5857, 1705, 3868, 3779, 4397, 2177,
	159,  622, 2240, 1275,  640, 6948, 4572, 5277,  209, 2605, 1157, 7328, 5817, 3191, 1662, 2009,
	4864,  574, 2487,  164, 6197, 4436, 7257, 3462, 4268, 4281, 3414, 4515, 3170, 1290, 2003, 5855,
	7156, 6062, 7531, 1732, 3249, 4884, 7512, 3590, 1049, 2123, 1397, 6093, 3691, 6130, 6541, 3946,
	6258, 3322, 1788, 4241, 4900, 2309, 1400, 1757,  400,  502, 6698, 2338, 3011,  668, 7444, 4580,
	6516, 6795, 2959, 4136, 3040, 2279, 6355, 3943, 2913, 6613, 7416, 4084, 6508, 5556, 4054, 3782,
	61, 6567, 2212,  779,  632, 5709, 5667, 4923, 4911, 6893, 4695, 4164, 3536, 2287, 7594, 2848,
	3267, 1911, 3128,  546, 1991,  156, 4958, 5531, 6903,  483,  875,  138,  250, 2234, 2266, 7222,
	2842, 4258,  812, 6703,  232, 5207, 6650, 2585, 1900, 6225, 4932, 7265, 4701, 3173, 4635, 6393,
	227, 7313, 4454, 4284, 6759, 1224, 5223, 1447,  395, 2608, 4502, 4037,  189, 3348,   54, 6443,
	2210, 6230, 2826, 1780, 3002, 5995, 1955, 6102, 6045, 3938, 5019, 4417, 1434, 1262, 1507, 5847,
	5917, 7157, 7177, 6434, 7537,  741, 4348, 1309,  145,  374, 2236, 4496, 5028, 6771, 6923, 7421,
	1978, 1023, 3857, 6876, 1102, 7451, 4704, 6518, 1344,  765,  384, 5705, 1207, 1630, 4734, 1563,
	6839, 5933, 1954, 4987, 7142, 5814, 7527, 4953, 7637, 4707, 2182, 5734, 2818,  541, 4097, 5641 };



extern const uint16_t omegas_inv_bitrev_montgomery[];
extern const uint16_t psis_inv_montgomery[];
extern const uint16_t zetas[];


#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))
#define _GNU_SOURCE

static int fd = -1;
static const uint32_t qinv = 7679; // -inverse_mod(q,2^18)
static const uint32_t rlog = 18;

/*************************************************
* Name:        load64
*
* Description: Load 8 bytes into uint64_t in little-endian order
*
* Arguments:   - const unsigned char *x: pointer to input byte array
*
* Returns the loaded 64-bit unsigned integer
**************************************************/
static uint64_t load64_kyber(const unsigned char *x)
{
  unsigned long long r = 0, i;

  for (i = 0; i < 8; ++i) {
    r |= (unsigned long long)x[i] << 8 * i;
  }
  return r;
}

/*************************************************
* Name:        store64
*
* Description: Store a 64-bit integer to a byte array in little-endian order
*
* Arguments:   - uint8_t *x: pointer to the output byte array
*              - uint64_t u: input 64-bit unsigned integer
**************************************************/
static void store64_kyber(uint8_t *x, uint64_t u)
{
  unsigned int i;

  for(i=0; i<8; ++i) {
    x[i] = u;
    u >>= 8;
  }
}

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants_kyber[NROUNDS] =
{
    (uint64_t)0x0000000000000001ULL,
    (uint64_t)0x0000000000008082ULL,
    (uint64_t)0x800000000000808aULL,
    (uint64_t)0x8000000080008000ULL,
    (uint64_t)0x000000000000808bULL,
    (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008081ULL,
    (uint64_t)0x8000000000008009ULL,
    (uint64_t)0x000000000000008aULL,
    (uint64_t)0x0000000000000088ULL,
    (uint64_t)0x0000000080008009ULL,
    (uint64_t)0x000000008000000aULL,
    (uint64_t)0x000000008000808bULL,
    (uint64_t)0x800000000000008bULL,
    (uint64_t)0x8000000000008089ULL,
    (uint64_t)0x8000000000008003ULL,
    (uint64_t)0x8000000000008002ULL,
    (uint64_t)0x8000000000000080ULL,
    (uint64_t)0x000000000000800aULL,
    (uint64_t)0x800000008000000aULL,
    (uint64_t)0x8000000080008081ULL,
    (uint64_t)0x8000000000008080ULL,
    (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008008ULL
};

/*************************************************
* Name:        KeccakF1600_StatePermute
*
* Description: The Keccak F1600 Permutation
*
* Arguments:   - uint64_t * state: pointer to in/output Keccak state
**************************************************/
void KeccakF1600_StatePermute_kyber(uint64_t * state)
{
  int round;

        uint64_t Aba, Abe, Abi, Abo, Abu;
        uint64_t Aga, Age, Agi, Ago, Agu;
        uint64_t Aka, Ake, Aki, Ako, Aku;
        uint64_t Ama, Ame, Ami, Amo, Amu;
        uint64_t Asa, Ase, Asi, Aso, Asu;
        uint64_t BCa, BCe, BCi, BCo, BCu;
        uint64_t Da, De, Di, Do, Du;
        uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
        uint64_t Ega, Ege, Egi, Ego, Egu;
        uint64_t Eka, Eke, Eki, Eko, Eku;
        uint64_t Ema, Eme, Emi, Emo, Emu;
        uint64_t Esa, Ese, Esi, Eso, Esu;

        //copyFromState(A, state)
        Aba = state[ 0];
        Abe = state[ 1];
        Abi = state[ 2];
        Abo = state[ 3];
        Abu = state[ 4];
        Aga = state[ 5];
        Age = state[ 6];
        Agi = state[ 7];
        Ago = state[ 8];
        Agu = state[ 9];
        Aka = state[10];
        Ake = state[11];
        Aki = state[12];
        Ako = state[13];
        Aku = state[14];
        Ama = state[15];
        Ame = state[16];
        Ami = state[17];
        Amo = state[18];
        Amu = state[19];
        Asa = state[20];
        Ase = state[21];
        Asi = state[22];
        Aso = state[23];
        Asu = state[24];

        for( round = 0; round < NROUNDS; round += 2 )
        {
            //    prepareTheta
            BCa = Aba^Aga^Aka^Ama^Asa;
            BCe = Abe^Age^Ake^Ame^Ase;
            BCi = Abi^Agi^Aki^Ami^Asi;
            BCo = Abo^Ago^Ako^Amo^Aso;
            BCu = Abu^Agu^Aku^Amu^Asu;

            //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = ROL(Age, 44);
            Aki ^= Di;
            BCi = ROL(Aki, 43);
            Amo ^= Do;
            BCo = ROL(Amo, 21);
            Asu ^= Du;
            BCu = ROL(Asu, 14);
            Eba =   BCa ^((~BCe)&  BCi );
            Eba ^= (uint64_t)KeccakF_RoundConstants_kyber[round];
            Ebe =   BCe ^((~BCi)&  BCo );
            Ebi =   BCi ^((~BCo)&  BCu );
            Ebo =   BCo ^((~BCu)&  BCa );
            Ebu =   BCu ^((~BCa)&  BCe );

            Abo ^= Do;
            BCa = ROL(Abo, 28);
            Agu ^= Du;
            BCe = ROL(Agu, 20);
            Aka ^= Da;
            BCi = ROL(Aka,  3);
            Ame ^= De;
            BCo = ROL(Ame, 45);
            Asi ^= Di;
            BCu = ROL(Asi, 61);
            Ega =   BCa ^((~BCe)&  BCi );
            Ege =   BCe ^((~BCi)&  BCo );
            Egi =   BCi ^((~BCo)&  BCu );
            Ego =   BCo ^((~BCu)&  BCa );
            Egu =   BCu ^((~BCa)&  BCe );

            Abe ^= De;
            BCa = ROL(Abe,  1);
            Agi ^= Di;
            BCe = ROL(Agi,  6);
            Ako ^= Do;
            BCi = ROL(Ako, 25);
            Amu ^= Du;
            BCo = ROL(Amu,  8);
            Asa ^= Da;
            BCu = ROL(Asa, 18);
            Eka =   BCa ^((~BCe)&  BCi );
            Eke =   BCe ^((~BCi)&  BCo );
            Eki =   BCi ^((~BCo)&  BCu );
            Eko =   BCo ^((~BCu)&  BCa );
            Eku =   BCu ^((~BCa)&  BCe );

            Abu ^= Du;
            BCa = ROL(Abu, 27);
            Aga ^= Da;
            BCe = ROL(Aga, 36);
            Ake ^= De;
            BCi = ROL(Ake, 10);
            Ami ^= Di;
            BCo = ROL(Ami, 15);
            Aso ^= Do;
            BCu = ROL(Aso, 56);
            Ema =   BCa ^((~BCe)&  BCi );
            Eme =   BCe ^((~BCi)&  BCo );
            Emi =   BCi ^((~BCo)&  BCu );
            Emo =   BCo ^((~BCu)&  BCa );
            Emu =   BCu ^((~BCa)&  BCe );

            Abi ^= Di;
            BCa = ROL(Abi, 62);
            Ago ^= Do;
            BCe = ROL(Ago, 55);
            Aku ^= Du;
            BCi = ROL(Aku, 39);
            Ama ^= Da;
            BCo = ROL(Ama, 41);
            Ase ^= De;
            BCu = ROL(Ase,  2);
            Esa =   BCa ^((~BCe)&  BCi );
            Ese =   BCe ^((~BCi)&  BCo );
            Esi =   BCi ^((~BCo)&  BCu );
            Eso =   BCo ^((~BCu)&  BCa );
            Esu =   BCu ^((~BCa)&  BCe );

            //    prepareTheta
            BCa = Eba^Ega^Eka^Ema^Esa;
            BCe = Ebe^Ege^Eke^Eme^Ese;
            BCi = Ebi^Egi^Eki^Emi^Esi;
            BCo = Ebo^Ego^Eko^Emo^Eso;
            BCu = Ebu^Egu^Eku^Emu^Esu;

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = ROL(Ege, 44);
            Eki ^= Di;
            BCi = ROL(Eki, 43);
            Emo ^= Do;
            BCo = ROL(Emo, 21);
            Esu ^= Du;
            BCu = ROL(Esu, 14);
            Aba =   BCa ^((~BCe)&  BCi );
            Aba ^= (uint64_t)KeccakF_RoundConstants_kyber[round+1];
            Abe =   BCe ^((~BCi)&  BCo );
            Abi =   BCi ^((~BCo)&  BCu );
            Abo =   BCo ^((~BCu)&  BCa );
            Abu =   BCu ^((~BCa)&  BCe );

            Ebo ^= Do;
            BCa = ROL(Ebo, 28);
            Egu ^= Du;
            BCe = ROL(Egu, 20);
            Eka ^= Da;
            BCi = ROL(Eka, 3);
            Eme ^= De;
            BCo = ROL(Eme, 45);
            Esi ^= Di;
            BCu = ROL(Esi, 61);
            Aga =   BCa ^((~BCe)&  BCi );
            Age =   BCe ^((~BCi)&  BCo );
            Agi =   BCi ^((~BCo)&  BCu );
            Ago =   BCo ^((~BCu)&  BCa );
            Agu =   BCu ^((~BCa)&  BCe );

            Ebe ^= De;
            BCa = ROL(Ebe, 1);
            Egi ^= Di;
            BCe = ROL(Egi, 6);
            Eko ^= Do;
            BCi = ROL(Eko, 25);
            Emu ^= Du;
            BCo = ROL(Emu, 8);
            Esa ^= Da;
            BCu = ROL(Esa, 18);
            Aka =   BCa ^((~BCe)&  BCi );
            Ake =   BCe ^((~BCi)&  BCo );
            Aki =   BCi ^((~BCo)&  BCu );
            Ako =   BCo ^((~BCu)&  BCa );
            Aku =   BCu ^((~BCa)&  BCe );

            Ebu ^= Du;
            BCa = ROL(Ebu, 27);
            Ega ^= Da;
            BCe = ROL(Ega, 36);
            Eke ^= De;
            BCi = ROL(Eke, 10);
            Emi ^= Di;
            BCo = ROL(Emi, 15);
            Eso ^= Do;
            BCu = ROL(Eso, 56);
            Ama =   BCa ^((~BCe)&  BCi );
            Ame =   BCe ^((~BCi)&  BCo );
            Ami =   BCi ^((~BCo)&  BCu );
            Amo =   BCo ^((~BCu)&  BCa );
            Amu =   BCu ^((~BCa)&  BCe );

            Ebi ^= Di;
            BCa = ROL(Ebi, 62);
            Ego ^= Do;
            BCe = ROL(Ego, 55);
            Eku ^= Du;
            BCi = ROL(Eku, 39);
            Ema ^= Da;
            BCo = ROL(Ema, 41);
            Ese ^= De;
            BCu = ROL(Ese, 2);
            Asa =   BCa ^((~BCe)&  BCi );
            Ase =   BCe ^((~BCi)&  BCo );
            Asi =   BCi ^((~BCo)&  BCu );
            Aso =   BCo ^((~BCu)&  BCa );
            Asu =   BCu ^((~BCa)&  BCe );
        }

        //copyToState(state, A)
        state[ 0] = Aba;
        state[ 1] = Abe;
        state[ 2] = Abi;
        state[ 3] = Abo;
        state[ 4] = Abu;
        state[ 5] = Aga;
        state[ 6] = Age;
        state[ 7] = Agi;
        state[ 8] = Ago;
        state[ 9] = Agu;
        state[10] = Aka;
        state[11] = Ake;
        state[12] = Aki;
        state[13] = Ako;
        state[14] = Aku;
        state[15] = Ama;
        state[16] = Ame;
        state[17] = Ami;
        state[18] = Amo;
        state[19] = Amu;
        state[20] = Asa;
        state[21] = Ase;
        state[22] = Asi;
        state[23] = Aso;
        state[24] = Asu;

        #undef    round
}

#include <string.h>
#define MIN(a, b) ((a) < (b) ? (a) : (b))


/*************************************************
* Name:        keccak_absorb
*
* Description: Absorb step of Keccak;
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - uint64_t *s:             pointer to (uninitialized) output Keccak state
*              - unsigned int r:          rate in bytes (e.g., 168 for SHAKE128)
*              - const unsigned char *m:  pointer to input to be absorbed into s
*              - unsigned long long mlen: length of input in bytes
*              - unsigned char p:         domain-separation byte for different Keccak-derived functions
**************************************************/
static void keccak_absorb_kyber(uint64_t *s,
                          unsigned int r,
                          const unsigned char *m, unsigned long long int mlen,
                          unsigned char p)
{
  unsigned long long i;
  unsigned char t[200];

  // Zero state
  for (i = 0; i < 25; ++i)
    s[i] = 0;

  while (mlen >= r)
  {
    for (i = 0; i < r / 8; ++i)
      s[i] ^= load64_kyber(m + 8 * i);

    KeccakF1600_StatePermute_kyber(s);
    mlen -= r;
    m += r;
  }

  for (i = 0; i < r; ++i)
    t[i] = 0;
  for (i = 0; i < mlen; ++i)
    t[i] = m[i];
  t[i] = p;
  t[r - 1] |= 128;
  for (i = 0; i < r / 8; ++i)
    s[i] ^= load64_kyber(t + 8 * i);
}


/*************************************************
* Name:        keccak_squeezeblocks
*
* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
*              Modifies the state. Can be called multiple times to keep squeezing,
*              i.e., is incremental.
*
* Arguments:   - unsigned char *h:               pointer to output blocks
*              - unsigned long long int nblocks: number of blocks to be squeezed (written to h)
*              - uint64_t *s:                    pointer to in/output Keccak state
*              - unsigned int r:                 rate in bytes (e.g., 168 for SHAKE128)
**************************************************/
static void keccak_squeezeblocks_kyber(unsigned char *h, unsigned long long int nblocks,
                                 uint64_t *s,
                                 unsigned int r)
{
  unsigned int i;
  while(nblocks > 0)
  {
    KeccakF1600_StatePermute_kyber(s);
    for(i=0;i<(r>>3);i++)
    {
      store64_kyber(h+8*i, s[i]);
    }
    h += r;
    nblocks--;
  }
}


/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of the SHAKE128 XOF.
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - uint64_t *s:                     pointer to (uninitialized) output Keccak state
*              - const unsigned char *input:      pointer to input to be absorbed into s
*              - unsigned long long inputByteLen: length of input in bytes
**************************************************/
void shake128_absorb_kyber(uint64_t *s, const unsigned char *input, unsigned int inputByteLen)
{
  keccak_absorb_kyber(s, SHAKE128_RATE, input, inputByteLen, 0x1F);
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes each.
*              Modifies the state. Can be called multiple times to keep squeezing,
*              i.e., is incremental.
*
* Arguments:   - unsigned char *output:      pointer to output blocks
*              - unsigned long long nblocks: number of blocks to be squeezed (written to output)
*              - uint64_t *s:                pointer to in/output Keccak state
**************************************************/
void shake128_squeezeblocks_kyber(unsigned char *output, unsigned long long nblocks, uint64_t *s)
{
  keccak_squeezeblocks_kyber(output, nblocks, s, SHAKE128_RATE);
}

/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - unsigned char *output:      pointer to output
*              - unsigned long long outlen:  requested output length in bytes
               - const unsigned char *input: pointer to input
               - unsigned long long inlen:   length of input in bytes
**************************************************/
void shake256_kyber(unsigned char *output, unsigned long long outlen,
              const unsigned char *input,  unsigned long long inlen)
{
  uint64_t s[25];
  unsigned char t[SHAKE256_RATE];
  unsigned long long nblocks = outlen/SHAKE256_RATE;
  size_t i;

  /* Absorb input */
  keccak_absorb_kyber(s, SHAKE256_RATE, input, inlen, 0x1F);

  /* Squeeze output */
  keccak_squeezeblocks_kyber(output, nblocks, s, SHAKE256_RATE);

  output+=nblocks*SHAKE256_RATE;
  outlen-=nblocks*SHAKE256_RATE;

  if(outlen)
  {
    keccak_squeezeblocks_kyber(t, 1, s, SHAKE256_RATE);
    for(i=0;i<outlen;i++)
      output[i] = t[i];
  }
}

/*************************************************
* Name:        sha3_256
*
* Description: SHA3-256 with non-incremental API
*
* Arguments:   - unsigned char *output:      pointer to output
*              - const unsigned char *input: pointer to input
*              - unsigned long long inlen:   length of input in bytes
**************************************************/
void sha3_256_kyber(unsigned char *output, const unsigned char *input,  unsigned long long inlen)
{
  uint64_t s[25];
  unsigned char t[SHA3_256_RATE];
  size_t i;

  /* Absorb input */
  keccak_absorb_kyber(s, SHA3_256_RATE, input, inlen, 0x06);

  /* Squeeze output */
  keccak_squeezeblocks_kyber(t, 1, s, SHA3_256_RATE);

  for(i=0;i<32;i++)
      output[i] = t[i];
}

/*************************************************
* Name:        sha3_512
*
* Description: SHA3-512 with non-incremental API
*
* Arguments:   - unsigned char *output:      pointer to output
*              - const unsigned char *input: pointer to input
*              - unsigned long long inlen:   length of input in bytes
**************************************************/
void sha3_512_kyber(unsigned char *output, const unsigned char *input,  unsigned long long inlen)
{
  uint64_t s[25];
  unsigned char t[SHA3_512_RATE];
  size_t i;

  /* Absorb input */
  keccak_absorb_kyber(s, SHA3_512_RATE, input, inlen, 0x06);

  /* Squeeze output */
  keccak_squeezeblocks_kyber(t, 1, s, SHA3_512_RATE);

  for(i=0;i<64;i++)
      output[i] = t[i];
}


/*************************************************
* Name:        verify
*
* Description: Compare two arrays for equality in constant time.
*
* Arguments:   const unsigned char *a: pointer to first byte array
*              const unsigned char *b: pointer to second byte array
*              size_t len:             length of the byte arrays
*
* Returns 0 if the byte arrays are equal, 1 otherwise
**************************************************/
int verify_kyber(const unsigned char *a, const unsigned char *b, size_t len)
{
	uint64_t r;
	size_t i;
	r = 0;

	for (i = 0; i<len; i++)
		r |= a[i] ^ b[i];

	r = (-r) >> 63;
	return r;
}

/*************************************************
* Name:        cmov
*
* Description: Copy len bytes from x to r if b is 1;
*              don't modify x if b is 0. Requires b to be in {0,1};
*              assumes two's complement representation of negative integers.
*              Runs in constant time.
*
* Arguments:   unsigned char *r:       pointer to output byte array
*              const unsigned char *x: pointer to input byte array
*              size_t len:             Amount of bytes to be copied
*              unsigned char b:        Condition bit; has to be in {0,1}
**************************************************/
void cmov_kyber(unsigned char *r, const unsigned char *x, size_t len, unsigned char b)
{
	size_t i;

	b = -b;
	for (i = 0; i<len; i++)
		r[i] ^= b & (x[i] ^ r[i]);
}

/*
static void randombytes_fallback_kyber(unsigned char *x, size_t xlen)
{
  int i;

  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom",O_RDONLY);
      if (fd != -1) break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd,x,i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}

#ifdef SYS_getrandom
void randombytes_kyber(unsigned char *buf,size_t buflen)
{
  size_t d = 0;
  int r;

  while(d<buflen)
  {
    errno = 0;
    r = syscall(SYS_getrandom, buf, buflen - d, 0);
    if(r < 0)
    {
      if (errno == EINTR) continue;
      randombytes_fallback_kyber(buf, buflen);
      return;
    }
    buf += r;
    d += r;
  }
}
#else
void randombytes_kyber(unsigned char *buf,size_t buflen)
{
  randombytes_fallback_kyber(buf,buflen);
}
#endif
*/
void randombytes_kyber(unsigned char* buf, size_t buflen)
{
    int i, flag;
    //sleep(10);
    for (i = 0; i < buflen; i++)
    {
          flag = rand()%255;
          buf[i] = (char)flag;
    }
}

/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q,
*              where R=2^18 (see value of rlog)
*
* Arguments:   - uint32_t a: input unsigned integer to be reduced; has to be in {0,...,2281446912}
*
* Returns:     unsigned integer in {0,...,2^13-1} congruent to a * R^-1 modulo q.
**************************************************/
uint16_t montgomery_reduce_kyber(uint32_t a)
{
	uint32_t u;

	u = (a * qinv);
	u &= ((1 << rlog) - 1);
	u *= KYBER_Q;
	a = a + u;
	return a >> rlog;
}


/*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              16-bit integer congruent to a mod q in {0,...,11768}
*
* Arguments:   - uint16_t a: input unsigned integer to be reduced
*
* Returns:     unsigned integer in {0,...,11768} congruent to a modulo q.
**************************************************/
uint16_t barrett_reduce_kyber(uint16_t a)
{
	uint32_t u;

	u = a >> 13;//((uint32_t) a * sinv) >> 16;
	u *= KYBER_Q;
	a -= u;
	return a;
}

/*************************************************
* Name:        freeze
*
* Description: Full reduction; given a 16-bit integer a, computes
*              unsigned integer a mod q.
*
* Arguments:   - uint16_t x: input unsigned integer to be reduced
*
* Returns:     unsigned integer in {0,...,q-1} congruent to a modulo q.
**************************************************/
uint16_t freeze_kyber(uint16_t x)
{
	uint16_t m, r;
	int16_t c;
	r = barrett_reduce_kyber(x);

	m = r - KYBER_Q;
	c = m;
	c >>= 15;
	r = m ^ ((r^m)&c);

	return r;
}

/*************************************************
* Name:        ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial (vector of 256 coefficients) in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *p: pointer to in/output polynomial
**************************************************/
void ntt_kyber(uint16_t *p)
{
	int level, start, j, k;
	uint16_t zeta, t;

	k = 1;
	for (level = 7; level >= 0; level--)
	{
		for (start = 0; start < KYBER_N; start = j + (1 << level))
		{
			zeta = zetas[k++];
			for (j = start; j < start + (1 << level); ++j)
			{
				t = montgomery_reduce_kyber((uint32_t)zeta * p[j + (1 << level)]);

				p[j + (1 << level)] = barrett_reduce_kyber(p[j] + 4 * KYBER_Q - t);

				if (level & 1) /* odd level */
					p[j] = p[j] + t; /* Omit reduction (be lazy) */
				else
					p[j] = barrett_reduce_kyber(p[j] + t);
			}
		}
	}
}

/*************************************************
* Name:        invntt
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT) of
*              a polynomial (vector of 256 coefficients) in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void invntt_kyber(uint16_t * a)
{
	int start, j, jTwiddle, level;
	uint16_t temp, W;
	uint32_t t;

	for (level = 0; level<8; level++)
	{
		for (start = 0; start < (1 << level); start++)
		{
			jTwiddle = 0;
			for (j = start; j<KYBER_N - 1; j += 2 * (1 << level))
			{
				W = omegas_inv_bitrev_montgomery[jTwiddle++];
				temp = a[j];

				if (level & 1) /* odd level */
					a[j] = barrett_reduce_kyber((temp + a[j + (1 << level)]));
				else
					a[j] = (temp + a[j + (1 << level)]); /* Omit reduction (be lazy) */

				t = (W * ((uint32_t)temp + 4 * KYBER_Q - a[j + (1 << level)]));

				a[j + (1 << level)] = montgomery_reduce_kyber(t);
			}
		}
	}

	for (j = 0; j < KYBER_N; j++)
		a[j] = montgomery_reduce_kyber((a[j] * psis_inv_montgomery[j]));
}

/*************************************************
* Name:        load_littleendian
*
* Description: load bytes into a 64-bit integer
*              in little-endian order
*
* Arguments:   - const unsigned char *x: pointer to input byte array
*              - bytes:                  number of bytes to load, has to be <= 8
*
* Returns 64-bit unsigned integer loaded from x
**************************************************/
static uint64_t load_littleendian_kyber(const unsigned char *x, int bytes)
{
	int i;
	uint64_t r = x[0];
	for (i = 1; i<bytes; i++)
		r |= (uint64_t)x[i] << (8 * i);
	return r;
}

/*************************************************
* Name:        cbd
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter KYBER_ETA
*
* Arguments:   - poly *r:                  pointer to output polynomial
*              - const unsigned char *buf: pointer to input byte array
**************************************************/
void cbd_kyber(poly_kyber *r, const unsigned char *buf)
{
#if KYBER_ETA == 3
	uint32_t t, d, a[4], b[4];
	int i, j;

	for (i = 0; i<KYBER_N / 4; i++)
	{
		t = load_littleendian_kyber(buf + 3 * i, 3);
		d = 0;
		for (j = 0; j<3; j++)
			d += (t >> j) & 0x249249;

		a[0] = d & 0x7;
		b[0] = (d >> 3) & 0x7;
		a[1] = (d >> 6) & 0x7;
		b[1] = (d >> 9) & 0x7;
		a[2] = (d >> 12) & 0x7;
		b[2] = (d >> 15) & 0x7;
		a[3] = (d >> 18) & 0x7;
		b[3] = (d >> 21);

		r->coeffs[4 * i + 0] = a[0] + KYBER_Q - b[0];
		r->coeffs[4 * i + 1] = a[1] + KYBER_Q - b[1];
		r->coeffs[4 * i + 2] = a[2] + KYBER_Q - b[2];
		r->coeffs[4 * i + 3] = a[3] + KYBER_Q - b[3];
	}
#elif KYBER_ETA == 4
	uint32_t t, d, a[4], b[4];
	int i, j;

	for (i = 0; i<KYBER_N / 4; i++)
	{
		t = load_littleendian_kyber(buf + 4 * i, 4);
		d = 0;
		for (j = 0; j<4; j++)
			d += (t >> j) & 0x11111111;

		a[0] = d & 0xf;
		b[0] = (d >> 4) & 0xf;
		a[1] = (d >> 8) & 0xf;
		b[1] = (d >> 12) & 0xf;
		a[2] = (d >> 16) & 0xf;
		b[2] = (d >> 20) & 0xf;
		a[3] = (d >> 24) & 0xf;
		b[3] = (d >> 28);

		r->coeffs[4 * i + 0] = a[0] + KYBER_Q - b[0];
		r->coeffs[4 * i + 1] = a[1] + KYBER_Q - b[1];
		r->coeffs[4 * i + 2] = a[2] + KYBER_Q - b[2];
		r->coeffs[4 * i + 3] = a[3] + KYBER_Q - b[3];
	}
#elif KYBER_ETA == 5
	uint64_t t, d, a[4], b[4];
	int i, j;

	for (i = 0; i<KYBER_N / 4; i++)
	{
		t = load_littleendian_kyber(buf + 5 * i, 5);
		d = 0;
		for (j = 0; j<5; j++)
			d += (t >> j) & 0x0842108421UL;

		a[0] = d & 0x1f;
		b[0] = (d >> 5) & 0x1f;
		a[1] = (d >> 10) & 0x1f;
		b[1] = (d >> 15) & 0x1f;
		a[2] = (d >> 20) & 0x1f;
		b[2] = (d >> 25) & 0x1f;
		a[3] = (d >> 30) & 0x1f;
		b[3] = (d >> 35);

		r->coeffs[4 * i + 0] = a[0] + KYBER_Q - b[0];
		r->coeffs[4 * i + 1] = a[1] + KYBER_Q - b[1];
		r->coeffs[4 * i + 2] = a[2] + KYBER_Q - b[2];
		r->coeffs[4 * i + 3] = a[3] + KYBER_Q - b[3];
	}
#else
#error "poly_getnoise in poly.c only supports eta in {3,4,5}"
#endif
}

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_compress_kyber(unsigned char *r, const polyvec_kyber *a)
{
	int i, j, k;
	uint16_t t[8];
	for (i = 0; i<KYBER_K; i++)
	{
		for (j = 0; j<KYBER_N / 8; j++)
		{
			for (k = 0; k<8; k++)
				t[k] = ((((uint32_t)freeze_kyber(a->vec[i].coeffs[8 * j + k]) << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7ff;

			r[11 * j + 0] = t[0] & 0xff;
			r[11 * j + 1] = (t[0] >> 8) | ((t[1] & 0x1f) << 3);
			r[11 * j + 2] = (t[1] >> 5) | ((t[2] & 0x03) << 6);
			r[11 * j + 3] = (t[2] >> 2) & 0xff;
			r[11 * j + 4] = (t[2] >> 10) | ((t[3] & 0x7f) << 1);
			r[11 * j + 5] = (t[3] >> 7) | ((t[4] & 0x0f) << 4);
			r[11 * j + 6] = (t[4] >> 4) | ((t[5] & 0x01) << 7);
			r[11 * j + 7] = (t[5] >> 1) & 0xff;
			r[11 * j + 8] = (t[5] >> 9) | ((t[6] & 0x3f) << 2);
			r[11 * j + 9] = (t[6] >> 6) | ((t[7] & 0x07) << 5);
			r[11 * j + 10] = (t[7] >> 3);
		}
		r += 352;
	}
}

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - unsigned char *a: pointer to input byte array
**************************************************/
void polyvec_decompress_kyber(polyvec_kyber *r, const unsigned char *a)
{
	int i, j;
	for (i = 0; i<KYBER_K; i++)
	{
		for (j = 0; j<KYBER_N / 8; j++)
		{
			r->vec[i].coeffs[8 * j + 0] = (((a[11 * j + 0] | (((uint32_t)a[11 * j + 1] & 0x07) << 8)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 1] = ((((a[11 * j + 1] >> 3) | (((uint32_t)a[11 * j + 2] & 0x3f) << 5)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 2] = ((((a[11 * j + 2] >> 6) | (((uint32_t)a[11 * j + 3] & 0xff) << 2) | (((uint32_t)a[11 * j + 4] & 0x01) << 10)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 3] = ((((a[11 * j + 4] >> 1) | (((uint32_t)a[11 * j + 5] & 0x0f) << 7)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 4] = ((((a[11 * j + 5] >> 4) | (((uint32_t)a[11 * j + 6] & 0x7f) << 4)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 5] = ((((a[11 * j + 6] >> 7) | (((uint32_t)a[11 * j + 7] & 0xff) << 1) | (((uint32_t)a[11 * j + 8] & 0x03) << 9)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 6] = ((((a[11 * j + 8] >> 2) | (((uint32_t)a[11 * j + 9] & 0x1f) << 6)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 7] = ((((a[11 * j + 9] >> 5) | (((uint32_t)a[11 * j + 10] & 0xff) << 3)) * KYBER_Q) + 1024) >> 11;
		}
		a += 352;
	}
}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))

void polyvec_compress_kyber(unsigned char *r, const polyvec_kyber *a)
{
	int i, j, k;
	uint16_t t[4];
	for (i = 0; i<KYBER_K; i++)
	{
		for (j = 0; j<KYBER_N / 4; j++)
		{
			for (k = 0; k<4; k++)
				t[k] = ((((uint32_t)freeze_kyber(a->vec[i].coeffs[4 * j + k]) << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3ff;

			r[5 * j + 0] = t[0] & 0xff;
			r[5 * j + 1] = (t[0] >> 8) | ((t[1] & 0x3f) << 2);
			r[5 * j + 2] = (t[1] >> 6) | ((t[2] & 0x0f) << 4);
			r[5 * j + 3] = (t[2] >> 4) | ((t[3] & 0x03) << 6);
			r[5 * j + 4] = (t[3] >> 2);
		}
		r += 320;
	}
}

void polyvec_decompress_kyber(polyvec_kyber *r, const unsigned char *a)
{
	int i, j;
	for (i = 0; i<KYBER_K; i++)
	{
		for (j = 0; j<KYBER_N / 4; j++)
		{
			r->vec[i].coeffs[4 * j + 0] = (((a[5 * j + 0] | (((uint32_t)a[5 * j + 1] & 0x03) << 8)) * KYBER_Q) + 512) >> 10;
			r->vec[i].coeffs[4 * j + 1] = ((((a[5 * j + 1] >> 2) | (((uint32_t)a[5 * j + 2] & 0x0f) << 6)) * KYBER_Q) + 512) >> 10;
			r->vec[i].coeffs[4 * j + 2] = ((((a[5 * j + 2] >> 4) | (((uint32_t)a[5 * j + 3] & 0x3f) << 4)) * KYBER_Q) + 512) >> 10;
			r->vec[i].coeffs[4 * j + 3] = ((((a[5 * j + 3] >> 6) | (((uint32_t)a[5 * j + 4] & 0xff) << 2)) * KYBER_Q) + 512) >> 10;
		}
		a += 320;
	}
}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 288))

void polyvec_compress_kyber(unsigned char *r, const polyvec_kyber *a)
{
	int i, j, k;
	uint16_t t[8];
	for (i = 0; i<KYBER_K; i++)
	{
		for (j = 0; j<KYBER_N / 8; j++)
		{
			for (k = 0; k<8; k++)
				t[k] = ((((uint32_t)freeze_kyber(a->vec[i].coeffs[8 * j + k]) << 9) + KYBER_Q / 2) / KYBER_Q) & 0x1ff;

			r[9 * j + 0] = t[0] & 0xff;
			r[9 * j + 1] = (t[0] >> 8) | ((t[1] & 0x7f) << 1);
			r[9 * j + 2] = (t[1] >> 7) | ((t[2] & 0x3f) << 2);
			r[9 * j + 3] = (t[2] >> 6) | ((t[3] & 0x1f) << 3);
			r[9 * j + 4] = (t[3] >> 5) | ((t[4] & 0x0f) << 4);
			r[9 * j + 5] = (t[4] >> 4) | ((t[5] & 0x07) << 5);
			r[9 * j + 6] = (t[5] >> 3) | ((t[6] & 0x03) << 6);
			r[9 * j + 7] = (t[6] >> 2) | ((t[7] & 0x01) << 7);
			r[9 * j + 8] = (t[7] >> 1);
		}
		r += 288;
	}
}

void polyvec_decompress_kyber(polyvec_kyber *r, const unsigned char *a)
{
	int i, j;
	for (i = 0; i<KYBER_K; i++)
	{
		for (j = 0; j<KYBER_N / 8; j++)
		{
			r->vec[i].coeffs[8 * j + 0] = (((a[9 * j + 0] | (((uint32_t)a[9 * j + 1] & 0x01) << 8)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 1] = ((((a[9 * j + 1] >> 1) | (((uint32_t)a[9 * j + 2] & 0x03) << 7)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 2] = ((((a[9 * j + 2] >> 2) | (((uint32_t)a[9 * j + 3] & 0x07) << 6)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 3] = ((((a[9 * j + 3] >> 3) | (((uint32_t)a[9 * j + 4] & 0x0f) << 5)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 4] = ((((a[9 * j + 4] >> 4) | (((uint32_t)a[9 * j + 5] & 0x1f) << 4)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 5] = ((((a[9 * j + 5] >> 5) | (((uint32_t)a[9 * j + 6] & 0x3f) << 3)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 6] = ((((a[9 * j + 6] >> 6) | (((uint32_t)a[9 * j + 7] & 0x7f) << 2)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 7] = ((((a[9 * j + 7] >> 7) | (((uint32_t)a[9 * j + 8] & 0xff) << 1)) * KYBER_Q) + 256) >> 9;
		}
		a += 288;
	}
}


#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 256))

void polyvec_compress_kyber(unsigned char *r, const polyvec_kyber *a)
{
	int i, j, k;
	uint16_t t;
	for (i = 0; i<KYBER_K; i++)
	{
		for (j = 0; j<KYBER_N; j++)
		{
			r[j] = ((((uint32_t)freeze_kyber(a->vec[i].coeffs[j]) << 8) + KYBER_Q / 2) / KYBER_Q) & 0xff;
		}
		r += 256;
	}
}

void polyvec_decompress_kyber(polyvec_kyber *r, const unsigned char *a)
{
	int i, j;
	for (i = 0; i<KYBER_K; i++)
	{
		for (j = 0; j<KYBER_N; j++)
		{
			r->vec[i].coeffs[j] = ((a[j] * KYBER_Q) + 128) >> 8;
		}
		a += 256;
	}
}

#else
#error "Unsupported compression of polyvec"
#endif

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_tobytes_kyber(unsigned char *r, const polyvec_kyber *a)
{
	int i;
	for (i = 0; i<KYBER_K; i++)
		poly_tobytes_kyber(r + i * KYBER_POLYBYTES, &a->vec[i]);
}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_frombytes_kyber(polyvec_kyber *r, const unsigned char *a)
{
	int i;
	for (i = 0; i<KYBER_K; i++)
		poly_frombytes_kyber(&r->vec[i], a + i * KYBER_POLYBYTES);
}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_ntt_kyber(polyvec_kyber *r)
{
	int i;
	for (i = 0; i<KYBER_K; i++)
		poly_ntt_kyber(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_invntt
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_invntt_kyber(polyvec_kyber *r)
{
	int i;
	for (i = 0; i<KYBER_K; i++)
		poly_invntt_kyber(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_pointwise_acc
*
* Description: Pointwise multiply elements of a and b and accumulate into r
*
* Arguments: - poly *r:          pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_pointwise_acc_kyber(poly_kyber *r, const polyvec_kyber *a, const polyvec_kyber *b)
{
	int i, j;
	uint16_t t;
	for (j = 0; j<KYBER_N; j++)
	{
		t = montgomery_reduce_kyber(4613 * (uint32_t)b->vec[0].coeffs[j]); // 4613 = 2^{2*18} % q
		r->coeffs[j] = montgomery_reduce_kyber(a->vec[0].coeffs[j] * t);
		for (i = 1; i<KYBER_K; i++)
		{
			t = montgomery_reduce_kyber(4613 * (uint32_t)b->vec[i].coeffs[j]);
			r->coeffs[j] += montgomery_reduce_kyber(a->vec[i].coeffs[j] * t);
		}
		r->coeffs[j] = barrett_reduce_kyber(r->coeffs[j]);
	}
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_add_kyber(polyvec_kyber *r, const polyvec_kyber *a, const polyvec_kyber *b)
{
	int i;
	for (i = 0; i<KYBER_K; i++)
		poly_add_kyber(&r->vec[i], &a->vec[i], &b->vec[i]);

}

/*************************************************
* Name:        poly_compress
*
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const poly *a:    pointer to input polynomial
**************************************************/
void poly_compress_kyber(unsigned char *r, const poly_kyber *a)
{
	uint32_t t[8];
	unsigned int i, j, k = 0;

	for (i = 0; i<KYBER_N; i += 8)
	{
		for (j = 0; j<8; j++)
			t[j] = (((freeze_kyber(a->coeffs[i + j]) << 3) + KYBER_Q / 2) / KYBER_Q) & 7;

		r[k] = t[0] | (t[1] << 3) | (t[2] << 6);
		r[k + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[k + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
		k += 3;
	}
}

/*************************************************
* Name:        poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of poly_compress
*
* Arguments:   - poly *r:                pointer to output polynomial
*              - const unsigned char *a: pointer to input byte array
**************************************************/
void poly_decompress_kyber(poly_kyber *r, const unsigned char *a)
{
	unsigned int i;
	for (i = 0; i<KYBER_N; i += 8)
	{
		r->coeffs[i + 0] = (((a[0] & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 1] = ((((a[0] >> 3) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 2] = ((((a[0] >> 6) | ((a[1] << 2) & 4)) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 3] = ((((a[1] >> 1) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 4] = ((((a[1] >> 4) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 5] = ((((a[1] >> 7) | ((a[2] << 1) & 6)) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 6] = ((((a[2] >> 2) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 7] = ((((a[2] >> 5)) * KYBER_Q) + 4) >> 3;
		a += 3;
	}
}

/*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const poly *a:    pointer to input polynomial
**************************************************/
void poly_tobytes_kyber(unsigned char *r, const poly_kyber *a)
{
	int i, j;
	uint16_t t[8];

	for (i = 0; i<KYBER_N / 8; i++)
	{
		for (j = 0; j<8; j++)
			t[j] = freeze_kyber(a->coeffs[8 * i + j]);

		r[13 * i + 0] = t[0] & 0xff;
		r[13 * i + 1] = (t[0] >> 8) | ((t[1] & 0x07) << 5);
		r[13 * i + 2] = (t[1] >> 3) & 0xff;
		r[13 * i + 3] = (t[1] >> 11) | ((t[2] & 0x3f) << 2);
		r[13 * i + 4] = (t[2] >> 6) | ((t[3] & 0x01) << 7);
		r[13 * i + 5] = (t[3] >> 1) & 0xff;
		r[13 * i + 6] = (t[3] >> 9) | ((t[4] & 0x0f) << 4);
		r[13 * i + 7] = (t[4] >> 4) & 0xff;
		r[13 * i + 8] = (t[4] >> 12) | ((t[5] & 0x7f) << 1);
		r[13 * i + 9] = (t[5] >> 7) | ((t[6] & 0x03) << 6);
		r[13 * i + 10] = (t[6] >> 2) & 0xff;
		r[13 * i + 11] = (t[6] >> 10) | ((t[7] & 0x1f) << 3);
		r[13 * i + 12] = (t[7] >> 5);
	}

}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes
*
* Arguments:   - poly *r:                pointer to output polynomial
*              - const unsigned char *a: pointer to input byte array
**************************************************/
void poly_frombytes_kyber(poly_kyber *r, const unsigned char *a)
{
	int i;
	for (i = 0; i<KYBER_N / 8; i++)
	{
		r->coeffs[8 * i + 0] = a[13 * i + 0] | (((uint16_t)a[13 * i + 1] & 0x1f) << 8);
		r->coeffs[8 * i + 1] = (a[13 * i + 1] >> 5) | (((uint16_t)a[13 * i + 2]) << 3) | (((uint16_t)a[13 * i + 3] & 0x03) << 11);
		r->coeffs[8 * i + 2] = (a[13 * i + 3] >> 2) | (((uint16_t)a[13 * i + 4] & 0x7f) << 6);
		r->coeffs[8 * i + 3] = (a[13 * i + 4] >> 7) | (((uint16_t)a[13 * i + 5]) << 1) | (((uint16_t)a[13 * i + 6] & 0x0f) << 9);
		r->coeffs[8 * i + 4] = (a[13 * i + 6] >> 4) | (((uint16_t)a[13 * i + 7]) << 4) | (((uint16_t)a[13 * i + 8] & 0x01) << 12);
		r->coeffs[8 * i + 5] = (a[13 * i + 8] >> 1) | (((uint16_t)a[13 * i + 9] & 0x3f) << 7);
		r->coeffs[8 * i + 6] = (a[13 * i + 9] >> 6) | (((uint16_t)a[13 * i + 10]) << 2) | (((uint16_t)a[13 * i + 11] & 0x07) << 10);
		r->coeffs[8 * i + 7] = (a[13 * i + 11] >> 3) | (((uint16_t)a[13 * i + 12]) << 5);
	}
}

/*************************************************
* Name:        poly_getnoise
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA
*
* Arguments:   - poly *r:                   pointer to output polynomial
*              - const unsigned char *seed: pointer to input seed
*              - unsigned char nonce:       one-byte input nonce
**************************************************/
void poly_getnoise_kyber(poly_kyber *r, const unsigned char *seed, unsigned char nonce)
{
	unsigned char buf[KYBER_ETA*KYBER_N / 4];
	unsigned char extseed[KYBER_SYMBYTES + 1];
	int i;

	for (i = 0; i<KYBER_SYMBYTES; i++)
		extseed[i] = seed[i];
	extseed[KYBER_SYMBYTES] = nonce;

	shake256_kyber(buf, KYBER_ETA*KYBER_N / 4, extseed, KYBER_SYMBYTES + 1);

	cbd_kyber(r, buf);
}

/*************************************************
* Name:        poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
void poly_ntt_kyber(poly_kyber *r)
{
	ntt_kyber(r->coeffs);
}

/*************************************************
* Name:        poly_invntt
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void poly_invntt_kyber(poly_kyber *r)
{
	invntt_kyber(r->coeffs);
}

/*************************************************
* Name:        poly_add
*
* Description: Add two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_add_kyber(poly_kyber *r, const poly_kyber *a, const poly_kyber *b)
{
	int i;
	for (i = 0; i<KYBER_N; i++)
		r->coeffs[i] = barrett_reduce_kyber(a->coeffs[i] + b->coeffs[i]);
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void poly_sub_kyber(poly_kyber *r, const poly_kyber *a, const poly_kyber *b)
{
	int i;
	for (i = 0; i<KYBER_N; i++)
		r->coeffs[i] = barrett_reduce_kyber(a->coeffs[i] + 3 * KYBER_Q - b->coeffs[i]);
}

/*************************************************
* Name:        poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r:                  pointer to output polynomial
*              - const unsigned char *msg: pointer to input message
**************************************************/
void poly_frommsg_kyber(poly_kyber *r, const unsigned char msg[KYBER_SYMBYTES])
{
	uint16_t i, j, mask;

	for (i = 0; i<KYBER_SYMBYTES; i++)
	{
		for (j = 0; j<8; j++)
		{
			mask = -((msg[i] >> j) & 1);
			r->coeffs[8 * i + j] = mask & ((KYBER_Q + 1) / 2);
		}
	}
}

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - unsigned char *msg: pointer to output message
*              - const poly *a:      pointer to input polynomial
**************************************************/
void poly_tomsg_kyber(unsigned char msg[KYBER_SYMBYTES], const poly_kyber *a)
{
	uint16_t t;
	int i, j;

	for (i = 0; i<KYBER_SYMBYTES; i++)
	{
		msg[i] = 0;
		for (j = 0; j<8; j++)
		{
			t = (((freeze_kyber(a->coeffs[8 * i + j]) << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
			msg[i] |= t << j;
		}
	}
}

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              compressed and serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   unsigned char *r:          pointer to the output serialized public key
*              const poly *pk:            pointer to the input public-key polynomial
*              const unsigned char *seed: pointer to the input public seed
**************************************************/
void pack_pk_kyber(unsigned char *r, const polyvec_kyber *pk, const unsigned char *seed)
{
	int i;
	polyvec_compress_kyber(r, pk);
	for (i = 0; i<KYBER_SYMBYTES; i++)
		r[i + KYBER_POLYVECCOMPRESSEDBYTES] = seed[i];
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize and decompress public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk:                   pointer to output public-key vector of polynomials
*              - unsigned char *seed:           pointer to output seed to generate matrix A
*              - const unsigned char *packedpk: pointer to input serialized public key
**************************************************/
void unpack_pk_kyber(polyvec_kyber *pk, unsigned char *seed, const unsigned char *packedpk)
{
	int i;
	polyvec_decompress_kyber(pk, packedpk);

	for (i = 0; i<KYBER_SYMBYTES; i++)
		seed[i] = packedpk[i + KYBER_POLYVECCOMPRESSEDBYTES];
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   unsigned char *r:          pointer to the output serialized ciphertext
*              const poly *pk:            pointer to the input vector of polynomials b
*              const unsigned char *seed: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext_kyber(unsigned char *r, const polyvec_kyber *b, const poly_kyber *v)
{
	polyvec_compress_kyber(r, b);
	poly_compress_kyber(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b:             pointer to the output vector of polynomials b
*              - poly *v:                pointer to the output polynomial v
*              - const unsigned char *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext_kyber(polyvec_kyber *b, poly_kyber *v, const unsigned char *c)
{
	polyvec_decompress_kyber(b, c);
	poly_decompress_kyber(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - unsigned char *r:  pointer to output serialized secret key
*              - const polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
void pack_sk_kyber(unsigned char *r, const polyvec_kyber *sk)
{
	polyvec_tobytes_kyber(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key;
*              inverse of pack_sk
*
* Arguments:   - polyvec *sk:                   pointer to output vector of polynomials (secret key)
*              - const unsigned char *packedsk: pointer to input serialized secret key
**************************************************/
void unpack_sk_kyber(polyvec_kyber *sk, const unsigned char *packedsk)
{
	polyvec_frombytes_kyber(sk, packedsk);
}

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              SHAKE-128
*
* Arguments:   - polyvec *a:                pointer to ouptput matrix A
*              - const unsigned char *seed: pointer to input seed
*              - int transposed:            boolean deciding whether A or A^T is generated
**************************************************/
void gen_matrix_kyber(polyvec_kyber *a, const unsigned char *seed, int transposed) // Not static for benchmarking
{
	unsigned int pos = 0, ctr;
	uint16_t val;
	unsigned int nblocks;
	const unsigned int maxnblocks = 4;
	uint8_t buf[SHAKE128_RATE*maxnblocks];
	int i, j;
	uint64_t state[25]; // SHAKE state
	unsigned char extseed[KYBER_SYMBYTES + 2];

	for (i = 0; i<KYBER_SYMBYTES; i++)
		extseed[i] = seed[i];


	for (i = 0; i<KYBER_K; i++)
	{
		for (j = 0; j<KYBER_K; j++)
		{
			ctr = pos = 0;
			nblocks = maxnblocks;
			if (transposed)
			{
				extseed[KYBER_SYMBYTES] = i;
				extseed[KYBER_SYMBYTES + 1] = j;
			}
			else
			{
				extseed[KYBER_SYMBYTES] = j;
				extseed[KYBER_SYMBYTES + 1] = i;
			}

			shake128_absorb_kyber(state, extseed, KYBER_SYMBYTES + 2);
			shake128_squeezeblocks_kyber(buf, nblocks, state);

			while (ctr < KYBER_N)
			{
				val = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
				if (val < KYBER_Q)
				{
					a[i].vec[j].coeffs[ctr++] = val;
				}
				pos += 2;

				if (pos > SHAKE128_RATE*nblocks - 2)
				{
					nblocks = 1;
					shake128_squeezeblocks_kyber(buf, nblocks, state);
					pos = 0;
				}
			}
		}
	}
}


/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - unsigned char *pk: pointer to output public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void indcpa_keypair_kyber(unsigned char *pk,
	unsigned char *sk
)
{
	polyvec_kyber a[KYBER_K], e, pkpv, skpv;
	unsigned char buf[KYBER_SYMBYTES + KYBER_SYMBYTES];
	unsigned char *publicseed = buf;
	unsigned char *noiseseed = buf + KYBER_SYMBYTES;
	int i;
	unsigned char nonce = 0;

	randombytes_kyber(buf, KYBER_SYMBYTES);
	sha3_512_kyber(buf, buf, KYBER_SYMBYTES);
	gen_a(a, publicseed);

	for (i = 0; i<KYBER_K; i++)
		poly_getnoise_kyber(skpv.vec + i, noiseseed, nonce++);

	polyvec_ntt_kyber(&skpv);

	for (i = 0; i<KYBER_K; i++)
		poly_getnoise_kyber(e.vec + i, noiseseed, nonce++);

	// matrix-vector multiplication
	for (i = 0; i<KYBER_K; i++)
		polyvec_pointwise_acc_kyber(&pkpv.vec[i], &skpv, a + i);

	polyvec_invntt_kyber(&pkpv);
	polyvec_add_kyber(&pkpv, &pkpv, &e);

	pack_sk_kyber(sk, &skpv);
	pack_pk_kyber(pk, &pkpv, publicseed);
}


/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - unsigned char *c:          pointer to output ciphertext (of length KYBER_INDCPA_BYTES bytes)
*              - const unsigned char *m:    pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - const unsigned char *coin: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
*                                           to deterministically generate all randomness
**************************************************/
void indcpa_enc_kyber(unsigned char *c,
	const unsigned char *m,
	const unsigned char *pk,
	const unsigned char *coins)
{
	polyvec_kyber sp, pkpv, ep, at[KYBER_K], bp;
	poly_kyber v, k, epp;
	unsigned char seed[KYBER_SYMBYTES];
	int i;
	unsigned char nonce = 0;


	unpack_pk_kyber(&pkpv, seed, pk);

	poly_frommsg_kyber(&k, m);

	polyvec_ntt_kyber(&pkpv);

	gen_at(at, seed);

	for (i = 0; i<KYBER_K; i++)
		poly_getnoise_kyber(sp.vec + i, coins, nonce++);

	polyvec_ntt_kyber(&sp);

	for (i = 0; i<KYBER_K; i++)
		poly_getnoise_kyber(ep.vec + i, coins, nonce++);

	// matrix-vector multiplication
	for (i = 0; i<KYBER_K; i++)
		polyvec_pointwise_acc_kyber(&bp.vec[i], &sp, at + i);

	polyvec_invntt_kyber(&bp);
	polyvec_add_kyber(&bp, &bp, &ep);

	polyvec_pointwise_acc_kyber(&v, &pkpv, &sp);
	poly_invntt_kyber(&v);

	poly_getnoise_kyber(&epp, coins, nonce++);

	poly_add_kyber(&v, &v, &epp);
	poly_add_kyber(&v, &v, &k);

	pack_ciphertext_kyber(c, &bp, &v);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - unsigned char *m:        pointer to output decrypted message (of length KYBER_INDCPA_MSGBYTES)
*              - const unsigned char *c:  pointer to input ciphertext (of length KYBER_INDCPA_BYTES)
*              - const unsigned char *sk: pointer to input secret key (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec_kyber(unsigned char *m,
	const unsigned char *c,
	const unsigned char *sk)
{
	polyvec_kyber bp, skpv;
	poly_kyber v, mp;

	unpack_ciphertext_kyber(&bp, &v, c);
	unpack_sk_kyber(&skpv, sk);

	polyvec_ntt_kyber(&bp);

	polyvec_pointwise_acc_kyber(&mp, &skpv, &bp);
	poly_invntt_kyber(&mp);

	poly_sub_kyber(&mp, &mp, &v);

	poly_tomsg_kyber(m, &mp);
}


/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair_kyber(unsigned char *pk, unsigned char *sk)
{
	size_t i;
	indcpa_keypair_kyber(pk, sk);
	for (i = 0; i<KYBER_INDCPA_PUBLICKEYBYTES; i++)
		sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
	sha3_256_kyber(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
	randombytes_kyber(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);         /* Value z for pseudo-random output on reject */
	return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct:       pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc_kyber(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
	unsigned char  kr[2 * KYBER_SYMBYTES];                                        /* Will contain key, coins */
	unsigned char buf[2 * KYBER_SYMBYTES];

	randombytes_kyber(buf, KYBER_SYMBYTES);
	sha3_256_kyber(buf, buf, KYBER_SYMBYTES);                                           /* Don't release system RNG output */

	sha3_256_kyber(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);                     /* Multitarget countermeasure for coins + contributory KEM */
	sha3_512_kyber(kr, buf, 2 * KYBER_SYMBYTES);

	indcpa_enc_kyber(ct, buf, pk, kr + KYBER_SYMBYTES);                                 /* coins are in kr+KYBER_SYMBYTES */

	sha3_256_kyber(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);                     /* overwrite coins in kr with H(c) */
	sha3_256_kyber(ss, kr, 2 * KYBER_SYMBYTES);                                         /* hash concatenation of pre-k and H(c) to k */
	return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *ct: pointer to input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - const unsigned char *sk: pointer to input private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec_kyber(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
	size_t i;
	int fail;
	unsigned char cmp[KYBER_CIPHERTEXTBYTES];
	unsigned char buf[2 * KYBER_SYMBYTES];
	unsigned char kr[2 * KYBER_SYMBYTES];                                         /* Will contain key, coins, qrom-hash */
	const unsigned char *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

	indcpa_dec_kyber(buf, ct, sk);

	for (i = 0; i<KYBER_SYMBYTES; i++)                                               /* Multitarget countermeasure for coins + contributory KEM */
		buf[KYBER_SYMBYTES + i] = sk[KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES + i];      /* Save hash by storing H(pk) in sk */
	sha3_512_kyber(kr, buf, 2 * KYBER_SYMBYTES);

	indcpa_enc_kyber(cmp, buf, pk, kr + KYBER_SYMBYTES);                                /* coins are in kr+KYBER_SYMBYTES */

	fail = verify_kyber(ct, cmp, KYBER_CIPHERTEXTBYTES);

	sha3_256_kyber(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);                     /* overwrite coins in kr with H(c)  */

	cmov_kyber(kr, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES, fail);     /* Overwrite pre-k with z on re-encryption failure */

	sha3_256_kyber(ss, kr, 2 * KYBER_SYMBYTES);                                         /* hash concatenation of pre-k and H(c) to k */

	return 0;
}
