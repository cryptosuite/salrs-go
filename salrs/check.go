package salrs


/*************************************************
* Name:        check_t_norm
*
* Description:    a function to check
*              whether the coefficients are in (-q/2, q/2)
*
* Arguments:   - polyveck *t: pointer to input t
*
* Returns 0/1. 1 means belonging to Rkq, 0 means not belonging to Rkq.
**************************************************/

func CheckTNorm(t polyveck) (flag bool) {
	var i, j int
	var f = true
	for i = 0; i < K; i++ {
		for j = 0; j < N; j++ {
			if (t.vec[i].coeffs[j] > Q2) || (t.vec[i].coeffs[j] < -Q2) {
				f = false
			}
		}
	}
	return f
}


func (t *polyveck) CheckNorm() bool {
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if (t.vec[i].coeffs[j] > Q2) || (t.vec[i].coeffs[j] < -Q2) {
				return false
			}
		}
	}
	return true
}

/*************************************************
 * Name:        check_z_norm
 *
 * Description:    a function to check
 *              whether the coefficients are in (-gamma_minus_two_theta_eta, gamma_minus_two_theta_eta)
 *
 * Arguments:   - polyvecl *z: pointer to input z
 *
 * Returns 0/1. 1 means belonging to S_L_gamma_minus_two_theta_eta, 0 means not belonging to S_L_gamma_minus_two_theta_eta.
 **************************************************/
func CheckZNorm(v polyvecl) (flag bool) {
	var i, j int
	var f = true
	for i = 0; i < L; i++ {
		for j = 0; j < N; j++ {
			if (v.vec[i].coeffs[j] > GammaMinusTwoEtaTheta) || (v.vec[i].coeffs[j] < -GammaMinusTwoEtaTheta) {
				//fmt.Println(v.vec[i].coeffs[j])
				f = false
			}
		}
	}
	return f
}

func (v *polyvecl) CheckNorm() bool {
	for i := 0; i < L; i++ {
		for j := 0; j < N; j++ {
			if (v.vec[i].coeffs[j] > GammaMinusTwoEtaTheta) || (v.vec[i].coeffs[j] < -GammaMinusTwoEtaTheta) {
				//fmt.Println(v.vec[i].coeffs[j])
				return false
			}
		}
	}
	return true
}

/*************************************************
 * Name:        check_c
 *
 * Description:    a function to check whether c has 256 coefficients
 *              , where 60 of them are 1/-1 and the rest are 0.
 *
 * Arguments:   - poly *c: pointer to input c
 *
 * Returns 0/1. 1 means belonging to B��, 0 means not belonging to B��.
 **************************************************/
// TODO: this function had been a method of poly, but maybe has some logic error
func CheckC(c poly) (flag bool) {
	var count, i = 0, 0
	var f = true
	for i = 0; i < N; i++ {
		if (c.coeffs[i] == 1) || (c.coeffs[i] == (-1)) {
			count++
		} else if c.coeffs[i] != 0 {
			f = false
		}
	}
	if count == 60 {
		f = true
	} else {
		f = false
	}
	return f
}
func (z *poly) CheckC() (flag bool) {
	count := 0
	flag = true
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

/*************************************************
 * Name:        equal_c
 *
 * Description:    a function to compare inputted c1 and c2
 *
 * Arguments:   - poly *c1: pointer to input c1
 *             - poly *c2: pointer to input c2
 *
 * Returns 0/1. 1 means c1 = c2, 0 means c1 �� c2.
 **************************************************/

func EqualC(c1 poly, c2 poly) (flag bool) {
	var i int
	var f = true
	for i = 0; i < N; i++ {
		if (c1.coeffs[i]) != (c2.coeffs[i]) {
			f = false
		}
	}
	return f
}
func (z *poly)EqualC(p *poly) bool {
	for i:=0;i< N;i++{
		if z.coeffs[i] != p.coeffs[i] {
			return false
		}
	}
	return true
}

/*************************************************
 * Name:        equal_I
 *
 * Description:    a function to compare inputted I1 and I2
 *
 * Arguments:   - polyvecm *I1: pointer to input I1
 *             - polyvecm *I2: pointer to input I2
 *
 * Returns 0/1. 1 means I1 = I2, 0 means I1 �� I2.
 **************************************************/
func EqualI(I1 polyvecm, I2 polyvecm) (flag bool) {
	var i, j int
	var f bool
	f = true
	for i = 0; i < M; i++ {
		for j = 0; j < N; j++ {
			if (I1.vec[i].coeffs[j]) != (I2.vec[i].coeffs[j]) {
				f = false
			}
		}
	}
	return f
}

func (v *polyvecm)Equal(p *polyvecm) bool {
	for i:=0;i<M;i++{
		if !v.vec[i].Equal(&p.vec[i]) {
			return false
		}
	}
	return true
}

/* TODO: whether here are some error about how to make a decision about two  polyveck equals
   and there should a method of polyveck which can judge two polyveck is equal  */
func Equaldpk(dpk1 DerivedPubKey, dpk2 DerivedPubKey) (flag bool) {
	var i, j, ii int
	var f bool
	f = true
	if dpk1.t != dpk2.t {
		f = false
		return f
	}
	i = len(dpk1.c)
	j = len(dpk2.c)
	if i != j {
		f = false
		return f
	}
	for ii = 0; ii < i; ii++ {
		if dpk1.c[ii] != dpk2.c[ii] {
			f = false
			return f
		}
	}
	return f
}

func (dpk *DerivedPubKey) Equal(k *DerivedPubKey) bool{
	if !dpk.t.Equal(&k.t)|| len(dpk.c) != len(k.c){
		return false
	}
	for i:=0;i<len(dpk.c);i++{
		if dpk.c[i]!=k.c[i] {
			return false
		}
	}
	return true
}