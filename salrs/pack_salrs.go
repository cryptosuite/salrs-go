package salrs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

//pack and unpack functions

/*************************************************
* Name:        pack_polyveck_q
*
* Description: Bit-pack t = As.
*
* Arguments:    - polyveck *t: pointer to input vector t
*              - unsigned char *t_char: pointer to output array
**************************************************/
func (t *polyveck) packQ() []byte {
	var tmp [2]int64
	res := make([]byte, PackTByteLen)
	offset := 0
	for i := 0; i < K; i++ {
		for j := 0; j < 128; j++ {
			// 2 * 36 = 9 * 8
			//add Q2 to be a positive number
			tmp[0] = t.vec[i].coeffs[2*j] + Q2
			tmp[1] = t.vec[i].coeffs[2*j+1] + Q2
			res[offset] = byte(tmp[0])                         //0-7
			res[offset+1] = byte(tmp[0] >> 8)                  //8-15
			res[offset+2] = byte(tmp[0] >> 16)                 //16-23
			res[offset+3] = byte(tmp[0] >> 24)                 //24-31
			res[offset+4] = byte(tmp[0]>>32) | byte(tmp[1]<<4) //32-35||0-3
			res[offset+5] = byte(tmp[1] >> 4)                  //4-11
			res[offset+6] = byte(tmp[1] >> 12)                 //12-19
			res[offset+7] = byte(tmp[1] >> 20)                 //20-27
			res[offset+8] = byte(tmp[1] >> 28)                 //28-35
			offset += 9
		}
	}
	return res
}
func packPolyveckQ(t polyveck) (tchar []byte) {
	var i, j int
	var tmp [2]int64
	tch := make([]byte, PackTByteLen)
	for i = 0; i < K; i++ {
		for j = 0; j < 128; j++ {
			tmp[0] = t.vec[i].coeffs[2*j] + Q2
			tmp[1] = t.vec[i].coeffs[2*j+1] + Q2
			tch[i*128*9+9*j+0] = byte(tmp[0])
			tch[i*128*9+9*j+1] = byte(tmp[0] >> 8)
			tch[i*128*9+9*j+2] = byte(tmp[0] >> 16)
			tch[i*128*9+9*j+3] = byte(tmp[0] >> 24)
			tch[i*128*9+9*j+4] = byte(tmp[0]>>32) | byte(tmp[1]<<4)
			tch[i*128*9+9*j+5] = byte(tmp[1] >> 4)
			tch[i*128*9+9*j+6] = byte(tmp[1] >> 12)
			tch[i*128*9+9*j+7] = byte(tmp[1] >> 20)
			tch[i*128*9+9*j+8] = byte(tmp[1] >> 28)
		}
	}
	return tch
}

/*************************************************
 * Name:        unpack_polyveck_q
 *
 * Description:  unpack t = As.
 *
 * Arguments:   - unsigned char *t_char: pointer to input array
 *              - polyveck *t: pointer to output vector t
 **************************************************/
func (t *polyveck) unpackQ(serializedBytes []byte) error {
	if len(serializedBytes) != PackTByteLen {
		return fmt.Errorf("the length of serialized derived public key is %d, but expected %d", len(serializedBytes), PackTByteLen)
	}
	var i, j int
	var tmp [2]int64
	for i = 0; i < K; i++ {
		for j = 0; j < 128; j++ {
			tmp[0] = int64(serializedBytes[i*128*9+9*j+0])
			tmp[0] |= (int64(serializedBytes[i*128*9+9*j+1])) << 8
			tmp[0] |= (int64(serializedBytes[i*128*9+9*j+2])) << 16
			tmp[0] |= (int64(serializedBytes[i*128*9+9*j+3])) << 24
			tmp[0] |= ((int64(serializedBytes[i*128*9+9*j+4])) << 32) & (0xFFFFFFFFF)
			tmp[1] = (int64(serializedBytes[i*128*9+9*j+4])) >> 4
			tmp[1] |= (int64(serializedBytes[i*128*9+9*j+5])) << 4
			tmp[1] |= (int64(serializedBytes[i*128*9+9*j+6])) << 12
			tmp[1] |= (int64(serializedBytes[i*128*9+9*j+7])) << 20
			tmp[1] |= ((int64(serializedBytes[i*128*9+9*j+8])) << 28) & (0xFFFFFFFFF)

			t.vec[i].coeffs[2*j] = tmp[0] - Q2
			t.vec[i].coeffs[2*j+1] = tmp[1] - Q2
		}
	}
	return nil
}
func unpackPolyveckQ(tchar []byte) (t polyveck) {
	var i, j int
	var tmp [2]int64
	var T polyveck
	for i = 0; i < K; i++ {
		for j = 0; j < 128; j++ {
			tmp[0] = int64(tchar[i*128*9+9*j+0])
			tmp[0] |= (int64(tchar[i*128*9+9*j+1])) << 8
			tmp[0] |= (int64(tchar[i*128*9+9*j+2])) << 16
			tmp[0] |= (int64(tchar[i*128*9+9*j+3])) << 24
			tmp[0] |= ((int64(tchar[i*128*9+9*j+4])) << 32) & (0xFFFFFFFFF)
			tmp[1] = (int64(tchar[i*128*9+9*j+4])) >> 4
			tmp[1] |= (int64(tchar[i*128*9+9*j+5])) << 4
			tmp[1] |= (int64(tchar[i*128*9+9*j+6])) << 12
			tmp[1] |= (int64(tchar[i*128*9+9*j+7])) << 20
			tmp[1] |= ((int64(tchar[i*128*9+9*j+8])) << 28) & (0xFFFFFFFFF)

			T.vec[i].coeffs[2*j] = tmp[0] - Q2
			T.vec[i].coeffs[2*j+1] = tmp[1] - Q2
		}
	}
	return T
}

/*************************************************
 * Name:        pack_polyvecl_eta
 *
 * Description: Bit-pack s <- Sl_eta.
 *
 * Arguments:    - polyvecl *s: pointer to input vector s
 *              - unsigned char *s_char: pointer to output array
 **************************************************/
func (s *polyvecl) packEta() []byte {
	var tmp [8]int64
	res := make([]byte, PackSByteLen)
	offset := 0
	for i := 0; i < L; i++ {
		for j := 0; j < 32; j++ {
			// 3 * 8 = 8 * 3
			tmp[0] = s.vec[i].coeffs[8*j+0] + Eta
			tmp[1] = s.vec[i].coeffs[8*j+1] + Eta
			tmp[2] = s.vec[i].coeffs[8*j+2] + Eta
			tmp[3] = s.vec[i].coeffs[8*j+3] + Eta
			tmp[4] = s.vec[i].coeffs[8*j+4] + Eta
			tmp[5] = s.vec[i].coeffs[8*j+5] + Eta
			tmp[6] = s.vec[i].coeffs[8*j+6] + Eta
			tmp[7] = s.vec[i].coeffs[8*j+7] + Eta

			res[offset] = byte(tmp[0]) + byte(tmp[1]<<3) + byte(tmp[2]<<6)                        //0-2||0-2||0-1
			res[offset+1] = byte(tmp[2]>>2) + byte(tmp[3]<<1) + byte(tmp[4]<<4) + byte(tmp[5]<<7) //2-2||0-2||0-2||0-0
			res[offset+2] = byte(tmp[5]>>1) + byte(tmp[6]<<2) + byte(tmp[7]<<5)                   //1-2||0-2||0-2
			offset += 3
		}
	}
	return res
}
func packPolyveclEta(s polyvecl) (schar []byte) {
	var i, j int
	var tmp [8]int64
	sch := make([]byte, PackSByteLen)
	for i = 0; i < L; i++ {
		for j = 0; j < 32; j++ {
			tmp[0] = s.vec[i].coeffs[8*j+0] + Eta
			tmp[1] = s.vec[i].coeffs[8*j+1] + Eta
			tmp[2] = s.vec[i].coeffs[8*j+2] + Eta
			tmp[3] = s.vec[i].coeffs[8*j+3] + Eta
			tmp[4] = s.vec[i].coeffs[8*j+4] + Eta
			tmp[5] = s.vec[i].coeffs[8*j+5] + Eta
			tmp[6] = s.vec[i].coeffs[8*j+6] + Eta
			tmp[7] = s.vec[i].coeffs[8*j+7] + Eta

			sch[i*32*3+j*3+0] = byte(tmp[0]) + byte(tmp[1]<<3) + byte(tmp[2]<<6)
			sch[i*32*3+j*3+1] = byte(tmp[2]>>2) + byte(tmp[3]<<1) + byte(tmp[4]<<4) + byte(tmp[5]<<7)
			sch[i*32*3+j*3+2] = byte(tmp[5]>>1) + byte(tmp[6]<<2) + byte(tmp[7]<<5)
		}
	}
	return sch
}

/*************************************************
 * Name:        unpack_polyvecl_eta
 *
 * Description: unpack s <- Sl_eta.
 *
 * Arguments:   - unsigned char *s_char: pointer to input array
 *              - polyvecl *s: pointer to output vector s
 **************************************************/
func (s *polyvecl) unpackEta(serializedBytes []byte) error {
	if len(serializedBytes) != PackSByteLen {
		return fmt.Errorf("the length of serialized derived public key is %d, but expected %d", len(serializedBytes), PackSByteLen)
	}
	var tmp [8]int64
	for i := 0; i < L; i++ {
		for j := 0; j < 32; j++ {
			tmp[0] = int64(serializedBytes[i*32*3+j*3+0] & 0x7)
			tmp[1] = int64(serializedBytes[i*32*3+j*3+0]) >> 3 & 0x7
			tmp[2] = (int64(serializedBytes[i*32*3+j*3+0]) >> 6 & 0x3) | (int64(serializedBytes[i*32*3+j*3+1]) << 2 & 0x4)
			tmp[3] = int64(serializedBytes[i*32*3+j*3+1]) >> 1 & 0x7
			tmp[4] = int64(serializedBytes[i*32*3+j*3+1]) >> 4 & 0x7
			tmp[5] = (int64(serializedBytes[i*32*3+j*3+1]) >> 7 & 0x1) | (int64(serializedBytes[i*32*3+j*3+2]) << 1 & 0x6)
			tmp[6] = int64(serializedBytes[i*32*3+j*3+2]) >> 2 & 0x7
			tmp[7] = int64(serializedBytes[i*32*3+j*3+2]) >> 5 & 0x7

			s.vec[i].coeffs[8*j+0] = tmp[0] - Eta
			s.vec[i].coeffs[8*j+1] = tmp[1] - Eta
			s.vec[i].coeffs[8*j+2] = tmp[2] - Eta
			s.vec[i].coeffs[8*j+3] = tmp[3] - Eta
			s.vec[i].coeffs[8*j+4] = tmp[4] - Eta
			s.vec[i].coeffs[8*j+5] = tmp[5] - Eta
			s.vec[i].coeffs[8*j+6] = tmp[6] - Eta
			s.vec[i].coeffs[8*j+7] = tmp[7] - Eta
		}
	}
	return nil
}
func unpackPolyveclEta(schar []byte) (s polyvecl) {
	var i, j int
	var tmp [8]int64
	var S polyvecl
	for i = 0; i < L; i++ {
		for j = 0; j < 32; j++ {
			tmp[0] = int64(schar[i*32*3+j*3+0] & 0x7)
			tmp[1] = int64(schar[i*32*3+j*3+0]) >> 3 & 0x7
			tmp[2] = (int64(schar[i*32*3+j*3+0]) >> 6 & 0x3) | (int64(schar[i*32*3+j*3+1]) << 2 & 0x4)
			tmp[3] = int64(schar[i*32*3+j*3+1]) >> 1 & 0x7
			tmp[4] = int64(schar[i*32*3+j*3+1]) >> 4 & 0x7
			tmp[5] = (int64(schar[i*32*3+j*3+1]) >> 7 & 0x1) | (int64(schar[i*32*3+j*3+2]) << 1 & 0x6)
			tmp[6] = int64(schar[i*32*3+j*3+2]) >> 2 & 0x7
			tmp[7] = int64(schar[i*32*3+j*3+2]) >> 5 & 0x7

			S.vec[i].coeffs[8*j+0] = tmp[0] - Eta
			S.vec[i].coeffs[8*j+1] = tmp[1] - Eta
			S.vec[i].coeffs[8*j+2] = tmp[2] - Eta
			S.vec[i].coeffs[8*j+3] = tmp[3] - Eta
			S.vec[i].coeffs[8*j+4] = tmp[4] - Eta
			S.vec[i].coeffs[8*j+5] = tmp[5] - Eta
			S.vec[i].coeffs[8*j+6] = tmp[6] - Eta
			S.vec[i].coeffs[8*j+7] = tmp[7] - Eta
		}
	}
	return S
}

/*************************************************
 * Name:        pack_polyvecl_gmte
 *
 * Description:  Bit-pack z <- Sl_gamma_minus_two_theta_eta.
 *
 * Arguments:   - polyvecl *z: pointer to input vector z
 *             - unsigned char *z_char: pointer to output array
 **************************************************/
func (z *polyvecl) packGmte() []byte {
	var tmp [4]int64
	res := make([]byte, PackZByteLen)
	offset := 0
	for i := 0; i < L; i++ {
		for j := 0; j < 64; j++ {
			//4 * 22  = 11 * 8  ?? right formate is 8 * 11 = 11 * 8
			// TODO: for testing
			tmp[0] = z.vec[i].coeffs[4*j+0] + GammaMinusTwoEtaTheta
			tmp[1] = z.vec[i].coeffs[4*j+1] + GammaMinusTwoEtaTheta
			tmp[2] = z.vec[i].coeffs[4*j+2] + GammaMinusTwoEtaTheta
			tmp[3] = z.vec[i].coeffs[4*j+3] + GammaMinusTwoEtaTheta
			res[offset+0] = byte(tmp[0])                               //0-7
			res[offset+1] = byte(tmp[0] >> 8)                          //8-15
			res[offset+2] = (byte(tmp[0] >> 16)) | (byte(tmp[1] << 6)) //16-21||0-1
			res[offset+3] = byte(tmp[1] >> 2)                          //2-10
			res[offset+4] = byte(tmp[1] >> 10)                         //11-18
			res[offset+5] = (byte(tmp[1] >> 18)) | (byte(tmp[2] << 4)) //19-21||0-3
			res[offset+6] = byte(tmp[2] >> 4)                          //4-11
			res[offset+7] = byte(tmp[2] >> 12)                         //12-19
			res[offset+8] = (byte(tmp[2] >> 20)) | (byte(tmp[3] << 2)) //20-21||0-5
			res[offset+9] = byte(tmp[3] >> 6)                          //6-13
			res[offset+10] = byte(tmp[3] >> 14)                        //14-21
			offset += 11
		}
	}
	return res
}
func packPolyveclGmte(z polyvecl) (zchar []byte) {
	var i, j int
	var tmp [4]int64
	zch := make([]byte, PackZByteLen)
	for i = 0; i < L; i++ {
		for j = 0; j < 64; j++ {
			tmp[0] = z.vec[i].coeffs[4*j+0] + GammaMinusTwoEtaTheta
			tmp[1] = z.vec[i].coeffs[4*j+1] + GammaMinusTwoEtaTheta
			tmp[2] = z.vec[i].coeffs[4*j+2] + GammaMinusTwoEtaTheta
			tmp[3] = z.vec[i].coeffs[4*j+3] + GammaMinusTwoEtaTheta
			zch[i*64*11+11*j+0] = byte(tmp[0])
			zch[i*64*11+11*j+1] = byte(tmp[0] >> 8)
			zch[i*64*11+11*j+2] = (byte(tmp[0] >> 16)) | (byte(tmp[1] << 6))
			zch[i*64*11+11*j+3] = byte(tmp[1] >> 2)
			zch[i*64*11+11*j+4] = byte(tmp[1] >> 10)
			zch[i*64*11+11*j+5] = (byte(tmp[1] >> 18)) | (byte(tmp[2] << 4))
			zch[i*64*11+11*j+6] = byte(tmp[2] >> 4)
			zch[i*64*11+11*j+7] = byte(tmp[2] >> 12)
			zch[i*64*11+11*j+8] = (byte(tmp[2] >> 20)) | (byte(tmp[3] << 2))
			zch[i*64*11+11*j+9] = byte(tmp[3] >> 6)
			zch[i*64*11+11*j+10] = byte(tmp[3] >> 14)
		}
	}
	return zch
}

/*************************************************
 * Name:        unpack_polyvecl_gmte
 *
 * Description:  Bit-pack z <- Sl_gamma_minus_two_theta_eta.
 *
 * Arguments:   - unsigned char *z_char: pointer to input array
 *              - polyvecl *z: pointer to output vector z
 **************************************************/
func (z *polyvecl) unpackGmte(serializedBytes []byte) error {
	if len(serializedBytes) != PackZByteLen {
		return fmt.Errorf("the length of serialized derived public key is %d, but expected %d", len(serializedBytes), PackZByteLen)
	}
	var tmp [4]int64
	for i := 0; i < L; i++ {
		for j := 0; j < 64; j++ {
			tmp[0] = int64(serializedBytes[i*64*11+11*j+0])
			tmp[0] |= (int64(serializedBytes[i*64*11+11*j+1])) << 8
			tmp[0] |= ((int64(serializedBytes[i*64*11+11*j+2])) << 16) & (0x3FFFFF)
			tmp[1] = (int64(serializedBytes[i*64*11+11*j+2])) >> 6
			tmp[1] |= (int64(serializedBytes[i*64*11+11*j+3])) << 2
			tmp[1] |= (int64(serializedBytes[i*64*11+11*j+4])) << 10
			tmp[1] |= (int64(serializedBytes[i*64*11+11*j+5]) << 18) & (0x3FFFFF)
			tmp[2] = int64(serializedBytes[i*64*11+11*j+5]) >> 4
			tmp[2] |= int64(serializedBytes[i*64*11+11*j+6]) << 4
			tmp[2] |= int64(serializedBytes[i*64*11+11*j+7]) << 12
			tmp[2] |= (int64(serializedBytes[i*64*11+11*j+8]) << 20) & (0x3FFFFF)
			tmp[3] = int64(serializedBytes[i*64*11+11*j+8]) >> 2
			tmp[3] |= int64(serializedBytes[i*64*11+11*j+9]) << 6
			tmp[3] |= (int64(serializedBytes[i*64*11+11*j+10]) << 14) & (0x3FFFFF)
			z.vec[i].coeffs[4*j+0] = tmp[0] - GammaMinusTwoEtaTheta
			z.vec[i].coeffs[4*j+1] = tmp[1] - GammaMinusTwoEtaTheta
			z.vec[i].coeffs[4*j+2] = tmp[2] - GammaMinusTwoEtaTheta
			z.vec[i].coeffs[4*j+3] = tmp[3] - GammaMinusTwoEtaTheta
		}
	}
	return nil
}
func unpackPolyveclGmte(zchar []byte) (z polyvecl) {
	var i, j int
	var tmp [4]int64
	var Z polyvecl
	for i = 0; i < L; i++ {
		for j = 0; j < 64; j++ {
			tmp[0] = int64(zchar[i*64*11+11*j+0])
			tmp[0] |= (int64(zchar[i*64*11+11*j+1])) << 8
			tmp[0] |= ((int64(zchar[i*64*11+11*j+2])) << 16) & (0x3FFFFF)
			tmp[1] = (int64(zchar[i*64*11+11*j+2])) >> 6
			tmp[1] |= (int64(zchar[i*64*11+11*j+3])) << 2
			tmp[1] |= (int64(zchar[i*64*11+11*j+4])) << 10
			tmp[1] |= (int64(zchar[i*64*11+11*j+5]) << 18) & (0x3FFFFF)
			tmp[2] = int64(zchar[i*64*11+11*j+5]) >> 4
			tmp[2] |= int64(zchar[i*64*11+11*j+6]) << 4
			tmp[2] |= int64(zchar[i*64*11+11*j+7]) << 12
			tmp[2] |= (int64(zchar[i*64*11+11*j+8]) << 20) & (0x3FFFFF)
			tmp[3] = int64(zchar[i*64*11+11*j+8]) >> 2
			tmp[3] |= int64(zchar[i*64*11+11*j+9]) << 6
			tmp[3] |= (int64(zchar[i*64*11+11*j+10]) << 14) & (0x3FFFFF)
			Z.vec[i].coeffs[4*j+0] = tmp[0] - GammaMinusTwoEtaTheta
			Z.vec[i].coeffs[4*j+1] = tmp[1] - GammaMinusTwoEtaTheta
			Z.vec[i].coeffs[4*j+2] = tmp[2] - GammaMinusTwoEtaTheta
			Z.vec[i].coeffs[4*j+3] = tmp[3] - GammaMinusTwoEtaTheta
		}
	}
	return Z
}

/*************************************************
 * Name:        pack_polyvecm_q
 *
 * Description:  Bit-pack m <- Rmq.
 *
 * Arguments:  - polyvecm *m: pointer to input vector m
 *            - unsigned char *m_char: pointer to output array
 **************************************************/
func (m *polyvecm) packQ() []byte {
	var tmp [2]int64
	res := make([]byte, PackIByteLen)
	offset := 0
	for i := 0; i < M; i++ {
		// 2 * 36 = 9 * 8
		for j := 0; j < 128; j++ {
			tmp[0] = m.vec[i].coeffs[2*j] + Q2
			tmp[1] = m.vec[i].coeffs[2*j+1] + Q2
			res[offset] = byte(tmp[0])                                 //0-8
			res[offset+1] = byte(tmp[0] >> 8)                          //9-15
			res[offset+2] = byte(tmp[0] >> 16)                         //16-23
			res[offset+3] = byte(tmp[0] >> 24)                         //24-31
			res[offset+4] = (byte(tmp[0] >> 32)) | (byte(tmp[1] << 4)) //32-35||0-3
			res[offset+5] = byte(tmp[1] >> 4)                          //4-11
			res[offset+6] = byte(tmp[1] >> 12)                         //12-19
			res[offset+7] = byte(tmp[1] >> 20)                         //20-27
			res[offset+8] = byte(tmp[1] >> 28)                         //28-35
			offset += 9
		}
	}
	return res
}
func packPolyvecmQ(m polyvecm) (mChar []byte) {
	var ii, j int
	var tmp [2]int64
	mCh := make([]byte, PackIByteLen)
	for ii = 0; ii < M; ii++ {
		for j = 0; j < 128; j++ {
			tmp[0] = m.vec[ii].coeffs[2*j] + Q2
			tmp[1] = m.vec[ii].coeffs[2*j+1] + Q2
			mCh[ii*128*9+9*j+0] = byte(tmp[0])
			mCh[ii*128*9+9*j+1] = byte(tmp[0] >> 8)
			mCh[ii*128*9+9*j+2] = byte(tmp[0] >> 16)
			mCh[ii*128*9+9*j+3] = byte(tmp[0] >> 24)
			mCh[ii*128*9+9*j+4] = (byte(tmp[0] >> 32)) | (byte(tmp[1] << 4))
			mCh[ii*128*9+9*j+5] = byte(tmp[1] >> 4)
			mCh[ii*128*9+9*j+6] = byte(tmp[1] >> 12)
			mCh[ii*128*9+9*j+7] = byte(tmp[1] >> 20)
			mCh[ii*128*9+9*j+8] = byte(tmp[1] >> 28)
		}
	}
	return mCh
}

/*************************************************
 * Name:        unpack_polyvecm_q
 *
 * Description:  unpack m <- Rmq.
 *
 * Arguments:   - unsigned char *m_char: pointer to input array
 *              - polyvecm *m: pointer to output vector m
 **************************************************/
func (m *polyvecm) unpackQ(serializedBytes []byte) error {
	if len(serializedBytes) != PackIByteLen {
		return fmt.Errorf("the length of serialized derived public key is %d, but expected %d", len(serializedBytes), PackIByteLen)
	}
	var tmp [2]int64
	for i := 0; i < M; i++ {
		for j := 0; j < 128; j++ {
			tmp[0] = int64(serializedBytes[i*128*9+9*j+0])
			tmp[0] |= int64(serializedBytes[i*128*9+9*j+1]) << 8
			tmp[0] |= int64(serializedBytes[i*128*9+9*j+2]) << 16
			tmp[0] |= int64(serializedBytes[i*128*9+9*j+3]) << 24
			tmp[0] |= (int64(serializedBytes[i*128*9+9*j+4]) << 32) & (0xFFFFFFFFF)
			tmp[1] = int64(serializedBytes[i*128*9+9*j+4]) >> 4
			tmp[1] |= int64(serializedBytes[i*128*9+9*j+5]) << 4
			tmp[1] |= int64(serializedBytes[i*128*9+9*j+6]) << 12
			tmp[1] |= int64(serializedBytes[i*128*9+9*j+7]) << 20
			tmp[1] |= (int64(serializedBytes[i*128*9+9*j+8]) << 28) & (0xFFFFFFFFF)

			m.vec[i].coeffs[2*j] = tmp[0] - Q2
			m.vec[i].coeffs[2*j+1] = tmp[1] - Q2
		}
	}
	return nil
}
func unpackPolyvecmQ(mChar []byte) (m polyvecm) {
	var ii, j int
	var tmp [2]int64
	var mm polyvecm
	for ii = 0; ii < M; ii++ {
		for j = 0; j < 128; j++ {
			tmp[0] = int64(mChar[ii*128*9+9*j+0])
			tmp[0] |= int64(mChar[ii*128*9+9*j+1]) << 8
			tmp[0] |= int64(mChar[ii*128*9+9*j+2]) << 16
			tmp[0] |= int64(mChar[ii*128*9+9*j+3]) << 24
			tmp[0] |= (int64(mChar[ii*128*9+9*j+4]) << 32) & (0xFFFFFFFFF)
			tmp[1] = int64(mChar[ii*128*9+9*j+4]) >> 4
			tmp[1] |= int64(mChar[ii*128*9+9*j+5]) << 4
			tmp[1] |= int64(mChar[ii*128*9+9*j+6]) << 12
			tmp[1] |= int64(mChar[ii*128*9+9*j+7]) << 20
			tmp[1] |= (int64(mChar[ii*128*9+9*j+8]) << 28) & (0xFFFFFFFFF)

			mm.vec[ii].coeffs[2*j] = tmp[0] - Q2
			mm.vec[ii].coeffs[2*j+1] = tmp[1] - Q2
		}
	}
	return mm
}

/*************************************************
 * Name:        pack_i
 *
 * Description:  Bit-pack i <- Rmq.
 *
 * Arguments:  - polyvecm *i: pointer to input vector i
 *            - unsigned char *i_char: pointer to output array
 **************************************************/
/**
  void pack_i(polyvecm *i,
  	unsigned char *i_char)
  {
  	int ii, j;
  	long long tmp[2];
  	for (ii = 0; ii < M; ++ii)
  	{
  		for (j = 0; j < 128; ++j)
  		{
  			tmp[0] = i->vec[ii].coeffs[2 * j] + Q_2;
  			tmp[1] = i->vec[ii].coeffs[2 * j + 1] + Q_2;
  			i_char[ii * 128 * 9 + 9 * j + 0] = (char)tmp[0];
  			i_char[ii * 128 * 9 + 9 * j + 1] = (char)(tmp[0] >> 8);
  			i_char[ii * 128 * 9 + 9 * j + 2] = (char)(tmp[0] >> 16);
  			i_char[ii * 128 * 9 + 9 * j + 3] = (char)(tmp[0] >> 24);
  			i_char[ii * 128 * 9 + 9 * j + 4] = ((char)(tmp[0] >> 32)) | ((char)(tmp[1] << 4));
  			i_char[ii * 128 * 9 + 9 * j + 5] = (char)(tmp[1] >> 4);
  			i_char[ii * 128 * 9 + 9 * j + 6] = (char)(tmp[1] >> 12);
  			i_char[ii * 128 * 9 + 9 * j + 7] = (char)(tmp[1] >> 20);
  			i_char[ii * 128 * 9 + 9 * j + 8] = (char)(tmp[1] >> 28);
  		}
  	}
  }
  **/

/*************************************************
 * Name:        unpack_i
 *
 * Description:  unpack i <- Rmq.
 *
 * Arguments:   - unsigned char *i_char: pointer to input array
 *              - polyvecm *i: pointer to output vector i
 **************************************************/
/**
  void unpack_i(unsigned char *i_char,
  	polyvecm *i)
  {
  	int ii, j;
  	long long tmp[2];
  	for (ii = 0; ii < M; ++ii)
  	{
  		for (j = 0; j < 128; ++j)
  		{
  			tmp[0] = (long long)i_char[ii * 128 * 9 + 9 * j + 0];
  			tmp[0] |= (long long)i_char[ii * 128 * 9 + 9 * j + 1] << 8;
  			tmp[0] |= (long long)i_char[ii * 128 * 9 + 9 * j + 2] << 16;
  			tmp[0] |= (long long)i_char[ii * 128 * 9 + 9 * j + 3] << 24;
  			tmp[0] |= ((long long)i_char[ii * 128 * 9 + 9 * j + 4] << 32)& (0xFFFFFFFFF);
  			tmp[1] = (long long)i_char[ii * 128 * 9 + 9 * j + 4] >> 4;
  			tmp[1] |= (long long)i_char[ii * 128 * 9 + 9 * j + 5] << 4;
  			tmp[1] |= (long long)i_char[ii * 128 * 9 + 9 * j + 6] << 12;
  			tmp[1] |= (long long)i_char[ii * 128 * 9 + 9 * j + 7] << 20;
  			tmp[1] |= ((long long)i_char[ii * 128 * 9 + 9 * j + 8] << 28)& (0xFFFFFFFFF);

  			i->vec[ii].coeffs[2 * j] = tmp[0] - Q_2;
  			i->vec[ii].coeffs[2 * j + 1] = tmp[1] - Q_2;
  		}
  	}
  }
  **/

/*************************************************
 * Name:        pack_mpk
 *
 * Description:  Bit-pack mpk.
 *
 * Arguments:   - unsigned char *pkkem: point to input pk in kem
 *              - polyveck *t: pointer to input vector t
 *              - unsigned char *mpk: pointer to output array mpk
 **************************************************/

/**
func packMpk(masterpk MasterPubKey) (mpk []byte) {
	var i int
	var mpkk := make([]byte, MpkByteLen)
	for i = 0; i < PKKEMByteLen; i++ {
		mpkk[i] = masterpk.pkkem[i]
	} //pk_kem string
	var sliceMpk [PackTByteLen]byte
	sliceMpk = packPolyveckQ(masterpk.t)
	for i = 0; i < PackTByteLen; i++ {
		mpkk[PKKEMByteLen+i] = sliceMpk[i]
	}
	return mpkk
}
**/

/*************************************************
 * Name:        unpack_mpk
 *
 * Description:  unpack mpk.
 *
 * Arguments:   - unsigned char *mpk: pointer to input array mpk
 *             - unsigned char *pkkem: point to output pk in kem
 *             - polyveck *t: pointer to output vector t
 **************************************************/
/**
func unpackMpk(mpk []byte) (masterpk MasterPubKey) {
	var i int
	masterpkk := MasterPubKey{}
	for i = 0; i < PKKEMByteLen; i++ {
		masterpkk.pkkem[i] = mpk[i]
	}
	//mpk += SIZE_PKKEM
	var sliceMpk [PackTByteLen]byte
	for i = 0; i < PackTByteLen; i++ {
		sliceMpk[i] = mpk[PKKEMByteLen+i]
	}
	masterpkk.t = unpackPolyveckQ(sliceMpk)
	return masterpkk
}
**/

/*************************************************
 * Name:        pack_msk
 *
 * Description:  Bit-pack msk.
 *
 * Arguments:   - unsigned char *skkem: point to input sk in kem
 *              - polyvecl *s: pointer to input vector s
 *              - unsigned char *msk: pointer to output array msk
 **************************************************/
/**
func packMsk(skkem []byte, s polyvecl) (msk []byte) {
	var i int
	var mskk := make([]byte, MskByteLen)
	for i = 0; i < SKKEMByteLen; i++ { //sk_kem string
		mskk[i] = skkem[i]
	}
	//msk += SIZE_SKKEM
	var sliceMsk := make([]byte, PackSByteLen)
	sliceMsk = packPolyveclEta(s)
	for i = 0; i < PackSByteLen; i++ {
		mskk[SKKEMByteLen+i] = sliceMsk[i]
	}

	return mskk
}
**/

/*************************************************
 * Name:        unpack_msk
 *
 * Description:  unpack msk.
 *
 * Arguments:   - unsigned char *msk: pointer to input array msk
 *             - unsigned char *skkem: point to output sk in kem
 *             - polyvecl *s: pointer to output vector s
 **************************************************/
/**
func unpackMsk(msk []byte) (skkem []byte, s polyvecl) {
	var i int
	var skkemm := make([]byte, SKKEMByteLen)
	var ss polyvecl
	for i = 0; i < SKKEMByteLen; i++ {
		skkemm[i] = msk[i]
	}
	//msk += SIZE_SKKEM
	var sliceMsk := make([]byte, PackSByteLen)
	for i = 0; i < PackSByteLen; i++ {
		sliceMsk[i] = msk[SKKEMByteLen+i]
	}
	ss = unpackPolyveclEta(sliceMsk)
	return skkemm, ss
}
**/

func (mpk *MasterPubKey) Serialize() []byte {
	b := make([]byte, MpkByteLen)
	offset := 0
	copy(b[offset:offset+PKKEMByteLen], mpk.pkkem.Bytes())
	offset += PKKEMByteLen
	copy(b[offset:], mpk.t.packQ())
	return b
}

func DeseralizeMasterPubKey(b []byte) (*MasterPubKey, error) {
	if len(b) != MpkByteLen {
		return nil, fmt.Errorf("the length of serialized derived public key is %d, but expected %d", len(b), MpkByteLen)
	}
	res := &MasterPubKey{}
	var err error
	res.pkkem, err = pkem.PublicKeyFromBytes(b[:PKKEMByteLen])
	if err != nil {
		return nil, errors.New("pubkey from byte failed")
	}
	err = res.t.unpackQ(b[PKKEMByteLen:])
	return res, err
}
func (msvk *MasterSecretViewKey) Serialize() []byte {
	return msvk.skkem.Bytes()
}

func DeseralizeMasterSecretViewKey(b []byte) (*MasterSecretViewKey, error) {
	if len(b) != MsvkByteLen {
		return nil, fmt.Errorf("the length of serialized master secret view  key is %d, but expected %d", len(b), MsvkByteLen)
	}
	var err error
	msvk := &MasterSecretViewKey{}
	msvk.skkem, err = pkem.SecretKeyFromBytes(b)
	return msvk, err
}
func (mssk *MasterSecretSignKey) Serialize() []byte {
	return mssk.S.packEta()
}

// TODO: lack handling error
func DeseralizeMasterSecretSignKey(b []byte) (*MasterSecretSignKey, error) {
	mssk := &MasterSecretSignKey{}
	var err error
	err = mssk.S.unpackEta(b)
	return mssk, err
}

/*************************************************
 * Name:        pack_dpk
 *
 * Description:  Bit-pack dpk.
 *
 * Arguments:   - unsigned char *c: point to input C in kem
 *              - polyveck *t: pointer to input vector t
 *              - unsigned char *dpk: pointer to output array dpk
 **************************************************/
func (dpk DerivedPubKey) Serialize() []byte {
	res := make([]byte, DpkByteLen)
	copy(res[:CipherByteLen], dpk.c)
	copy(res[CipherByteLen:], dpk.t.packQ())
	return res
}
func packDpk(derivedpk DerivedPubKey) (dpk []byte) {
	var i int
	dpkk := make([]byte, DpkByteLen)
	for i = 0; i < CipherByteLen; i++ { //cipher string
		dpkk[i] = derivedpk.c[i]
	}
	//dpk += SIZE_CIPHER
	sliceDpk := make([]byte, PackTByteLen)
	sliceDpk = packPolyveckQ(derivedpk.t)
	for i = 0; i < PackTByteLen; i++ {
		dpkk[CipherByteLen+i] = sliceDpk[i]
	}
	return dpkk
}

/*************************************************
 * Name:        unpack_dpk
 *
 * Description:  unpack dpk.
 *
 * Arguments:   - unsigned char *dpk: pointer to input array dpk
 *             - unsigned char *c: point to output C in kem
 *              - polyveck *t: pointer to output vector t
 **************************************************/
func DeseralizeDerivedPubKey(b []byte) (*DerivedPubKey, error) {
	if len(b) != DpkByteLen {
		return nil, fmt.Errorf("the length of serialized derived public key is %d, but expected %d", len(b), DpkByteLen)
	}
	res := &DerivedPubKey{}
	var err error
	if len(res.c)!=CipherByteLen{
		res.c=make([]byte,CipherByteLen)
	}
	copy(res.c[:], b[:CipherByteLen])
	err = res.t.unpackQ(b[CipherByteLen:])
	return res, err
}
func unpackDpk(dpk []byte) (derivedpk DerivedPubKey) {
	var i int
	derivedpkk := DerivedPubKey{}
	for i = 0; i < CipherByteLen; i++ {
		derivedpkk.c[i] = dpk[i]
	}
	//dpk += SIZE_CIPHER
	sliceDpk := make([]byte, PackTByteLen)
	for i = 0; i < PackTByteLen; i++ {
		sliceDpk[i] = dpk[CipherByteLen+i]
	}
	derivedpkk.t = unpackPolyveckQ(sliceDpk)
	return derivedpkk
}

/*************************************************
 * Name:        pack_sig
 *
 * Description:  Bit-pack sig.
 *
 * Arguments:   - poly *c: point to input c <- B\A6\C8
 *              - unsigned int r: r in {zi}ri=1
 *              - polyvecm* i: pointer to input i
 *              - unsigned char *sig: pointer to output array sig
 **************************************************/
func (sig Signature) Serialize() []byte {
	var res = make([]byte, 1+sig.r*PackZByteLen+PackIByteLen+N/8+8)
	offset := 0
	res[offset] = byte(sig.r)
	offset += 1
	for i := 0; i < sig.r; i++ {
		copy(res[offset:offset+PackZByteLen], sig.z[i].packGmte())
		offset += PackZByteLen
	}

	copy(res[offset:offset+PackIByteLen], sig.I.packQ())
	offset += PackIByteLen

	signs := int64(0)
	mask := int64(1)
	for i := 0; i < N/8; i++ {
		res[offset] = 0
		for j := 0; j < 8; j++ {
			if sig.c.coeffs[8*i+j] != 0 { // -1 or 1 will be encode with 1
				res[offset] |= byte(1 << j)
				if sig.c.coeffs[8*i+j] == 1 { // if 1, the sign will connect with 1, else 0
					signs |= mask
				}
				mask <<= 1
			}
		}
		offset += 1
	}
	binary.BigEndian.PutUint64(res[offset:], uint64(signs))
	return res
}
func packSig(sig Signature) (signature []byte) {
	var i2, j int
	var signs, mask, ii int64
	var signa = make([]byte, sig.r*PackZByteLen+PackIByteLen+N/8+8)

	/* Encode z*/
	//printf("encode z\n")

	slicez := make([]byte, PackZByteLen)
	for i2 = 0; i2 < sig.r; i2++ {
		slicez = packPolyveclGmte(sig.z[i2])
		for j = 0; j < PackZByteLen; j++ {
			signa[i2*PackZByteLen+j] = slicez[j]
		}
	}

	/* Encode I*/
	//printf("encode I\n")
	sliceI := make([]byte, PackIByteLen)
	//var sliceI = sig[r * PackZByteLen:r * PackZByteLen + PackIByteLen]
	sliceI = packPolyvecmQ(sig.I)
	for i2 = 0; i2 < PackIByteLen; i2++ {
		signa[sig.r*PackZByteLen+i2] = sliceI[i2]
	}

	/* Encode c */
	signs = 0
	mask = 1
	for i2 = 0; i2 < N/8; i2++ {
		signa[sig.r*PackZByteLen+PackIByteLen+i2] = 0
		for j = 0; j < 8; j++ {
			if sig.c.coeffs[8*i2+j] != 0 {
				signa[sig.r*PackZByteLen+PackIByteLen+i2] |= byte(uint32(1) << j)
				if sig.c.coeffs[8*i2+j] == (Q - 1) {
					signs |= mask
				}
				mask <<= 1
			}
		}
	}
	//sig += N / 8

	for ii = 0; ii < 8; ii++ {
		i2 = int(ii)
		signa[sig.r*PackZByteLen+PackIByteLen+N/8+i2] = byte(signs >> (8 * ii))
	}
	return signa
}

/*************************************************
 * Name:        unpack_sig
 *
 * Description:  unpack sig.
 *
 * Arguments:   - unsigned char *sig: pointer to input array sig
 *             - poly *c: point to output c <- B\A6\C8
 *              - unsigned int r: r in {zi}ri=1
 *              - polyvecm* i: pointer to output i
 **************************************************/
//func unpackSig(sig []byte, r uint32)(c poly,  i polyvecm, err error)
func DeserializeSignature(serializedBytes []byte) (*Signature, error) {
	sig := &Signature{}
	sig.r = int(serializedBytes[0])
	if len(serializedBytes) != 1+sig.r*PackZByteLen+PackIByteLen+N/8+8 {
		return nil, fmt.Errorf("the length of serialized derived public key is %d, but expected %d", len(serializedBytes), 1+sig.r*PackZByteLen+PackIByteLen+N/8+8)
	}

	signs := int64(binary.BigEndian.Uint64(serializedBytes[len(serializedBytes)-8:]))
	if signs>>60 != 0 {
		return nil, fmt.Errorf("the format of bytes is wrong in last 8 bits")
	}

	if len(sig.z) != sig.r {
		sig.z = make([]polyvecl, sig.r)
	}
	offset := 1

	for i := 0; i < sig.r; i++ {
		sig.z[i].unpackGmte(serializedBytes[offset : offset+PackZByteLen])
		offset += PackZByteLen
	}

	sig.I.unpackQ(serializedBytes[offset : offset+PackIByteLen])
	offset += PackIByteLen
	for i := 0; i < N/8; i++ {
		tmp:=serializedBytes[offset]
		for j:=0;j<8;j++{
			if (tmp>>j) & 0x01 == 1 {
				if signs&0x01 == 1 {
					sig.c.coeffs[i*8+j] = 1
				} else {
					sig.c.coeffs[i*8+j] = -1
				}
				signs >>= 1
			}
		}
	   offset+=1
	}
	return sig, nil
}
func unpackSig(signa []byte) (sig Signature, err error) {
	var ii, j int
	var signs, i2 int64
	sigg := Signature{}

	//calculate r
	var length int
	length = len(signa)
	var ring int
	ring = (length - (PackIByteLen + N/8 + 8)) / PackZByteLen
	sigg.r = ring

	/* Decode z*/
	var zz = make([]polyvecl, sigg.r)
	slicez := make([]byte, PackZByteLen)
	for ii = 0; ii < sigg.r; ii++ {
		for j = 0; j < PackZByteLen; j++ {
			slicez[j] = signa[ii*PackZByteLen+j]
			zz[j] = unpackPolyveclGmte(slicez)
		}
	}
	sigg.z = zz

	/* Decode I */
	sliceI := make([]byte, PackIByteLen)
	for ii = 0; ii < PackIByteLen; ii++ {
		sliceI[ii] = signa[ii+sigg.r*PackZByteLen]
	}
	sigg.I = unpackPolyvecmQ(sliceI)

	/* Decode c */
	for ii = 0; ii < N; ii++ {
		sigg.c.coeffs[ii] = 0
	}

	signs = 0
	for i2 = 0; i2 < 8; i2++ {
		signs |= int64(signa[sigg.r*PackZByteLen+PackIByteLen+N/8+int(i2)]) << 8 * i2
	}
	/* Extra sign bits are zero for strong unforgeability */
	if signs>>60 != 0 {
		return sigg, errors.New("sig unpack failed")
	}

	for ii = 0; ii < N/8; ii++ {
		for j = 0; j < 8; j++ {
			if (signa[sigg.r*PackZByteLen+PackIByteLen+ii]>>j)&0x01 == 1 {
				sigg.c.coeffs[8*ii+j] = 1
				sigg.c.coeffs[8*ii+j] ^= -(signs & 1) & (1 ^ (Q - 1))
				signs >>= 1
			}
		}
	}
	return sigg, nil
}

func (k KeyImage) Serialize() []byte {
	return k.I.packQ()
}
func DeserializeKeyImage(b []byte) (*KeyImage, error) {
	res := &KeyImage{}
	var err error
	err = res.I.unpackQ(b)
	return res, err
}
