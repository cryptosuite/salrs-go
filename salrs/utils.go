package salrs

import "bytes"
// TODO:the method of new added function can not resist the side-channel attack,
//  is it need to improve?
//reduce reduce the a into [-Q2,Q2]
func reduce(a int64) int64 {
	var tmp int64
	tmp = a % Q
	if tmp > Q2 {
		tmp -= Q
	}
	if tmp < -Q2 {
		tmp += Q
	}
	return tmp
}

func (p poly) Copy() *poly {
	res := NewPoly()
	for i := 0; i < N; i++ {
		res.coeffs[i] = p.coeffs[i]
	}
	return res
}
func (p *polyvecl) Copy() *polyvecl {
	res := new(polyvecl)
	for i := 0; i < L; i++ {
		res.vec[i] = *p.vec[i].Copy()
	}
	return res
}
func (p *polyveck) Copy() *polyveck {
	res := new(polyveck)
	for i := 0; i < K; i++ {
		res.vec[i] = *p.vec[i].Copy()
	}
	return res
}
func (p *polyvecm) Copy() *polyvecm {
	res := new(polyvecm)
	for i := 0; i < M; i++ {
		res.vec[i] = *p.vec[i].Copy()
	}
	return res
}

func (z *poly) Equal(a *poly) bool {
	for i := 0; i < N; i++ {
		if z.coeffs[i] != a.coeffs[i] {
			return false
		}
	}
	return true
}
func (t *polyveck) Equal(p *polyveck) bool {
	for i := 0; i < K; i++ {
		if !t.vec[i].Equal(&p.vec[i]) {
			return false
		}
	}
	return true
}
func (v *polyvecl) Equal(p *polyvecl) bool {
	for i := 0; i < L; i++ {
		if !v.vec[i].Equal(&p.vec[i]) {
			return false
		}
	}
	return true
}
func (v *polyvecm) Equal(p *polyvecm) bool {
	for i := 0; i < M; i++ {
		if !v.vec[i].Equal(&p.vec[i]) {
			return false
		}
	}
	return true
}

// Check check whether z has 256 coefficients,
// where 60 of them are 1/-1 and the rest are 0.
func (z *poly) CheckInOne() bool {
	count := 0
	for i := 0; i < N; i++ {
		if (z.coeffs[i] == 1) || (z.coeffs[i] == -1) {
			count++
		} else if z.coeffs[i] != 0 {
			return false
		}
	}
	if count == 60 {
		return true
	} else {
		return false
	}
}
func (z *poly) CheckInQ() bool {
	for i := 0; i < N; i++ {
		if (z.coeffs[i] > Q2) || (z.coeffs[i] < -Q2) {
			return false
		}
	}
	return true
}
func (z *poly) CheckInGmte() bool {
	for i := 0; i < N; i++ {
		if (z.coeffs[i] > GammaMinusTwoEtaTheta) || (z.coeffs[i] < -GammaMinusTwoEtaTheta) {
			return false
		}
	}
	return true
}
func (t *polyveck) CheckInQ() bool {
	for i := 0; i < K; i++ {
		if !t.vec[i].CheckInQ() {
			return false
		}
	}
	return true
}
func (v *polyvecl) CheckInGmte() bool {
	for i := 0; i < L; i++ {
		if !v.vec[i].CheckInGmte() {
			return false
		}
	}
	return true
}

func (mpk *MasterPubKey) Equal(k *MasterPubKey) bool {
	if !mpk.t.Equal(&k.t) {
		return false
	}
	return bytes.Equal(mpk.pkkem.Bytes(), k.pkkem.Bytes())
}
func (msvk *MasterSecretViewKey) Equal(k *MasterSecretViewKey) bool {
	return bytes.Equal(msvk.skkem.Bytes(), k.skkem.Bytes())
}
func (mssk *MasterSecretSignKey) Equal(k *MasterSecretSignKey) bool {
	return mssk.S.Equal(&k.S)
}
func (dpk *DerivedPubKey) Equal(k *DerivedPubKey) bool {
	if !dpk.t.Equal(&k.t) || len(dpk.c) != len(k.c) {
		return false
	}
	return bytes.Equal(dpk.c, k.c)
}
func (sig *Signature) Equal(s *Signature) bool {
	if sig.r!=s.r{
		return false
	}
	if !sig.c.Equal(&s.c) || !sig.I.Equal(&s.I){
		return false
	}
	for i:=0;i<sig.r;i++{
		if !sig.z[i].Equal(&s.z[i]){
			return false
		}
	}

	return true
}
