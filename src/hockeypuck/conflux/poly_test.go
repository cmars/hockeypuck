/*
   conflux - Distributed database synchronization library
	Based on the algorithm described in
		"Set Reconciliation with Nearly Optimal	Communication Complexity",
			Yaron Minsky, Ari Trachtenberg, and Richard Zippel, 2004.

   Copyright (c) 2012-2015  Casey Marshall <cmars@cmarstech.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package conflux

import (
	"math/big"

	gc "gopkg.in/check.v1"
)

type PolySuite struct{}

var _ = gc.Suite(&PolySuite{})

func (s *PolySuite) TestPolyDegree(c *gc.C) {
	p := big.NewInt(int64(65537))
	zero := Z(p)
	poly := NewPoly(Zi(p, 4), Zi(p, 3), Zi(p, 2))
	c.Assert(poly.Degree(), gc.Equals, 2)
	poly = NewPoly(zero, zero, zero, zero, zero, zero, zero, zero)
	c.Assert(poly.Degree(), gc.Equals, 0)
	poly = NewPoly(zero, zero, zero, zero, zero, zero, zero, Zi(p, 1))
	c.Assert(poly.Degree(), gc.Equals, 7)
	poly = NewPoly(zero, zero, zero, zero, zero, zero, zero, Zi(p, 1), zero, zero)
	c.Assert(poly.Degree(), gc.Equals, 7)
}

func (s *PolySuite) TestPolyFmt(c *gc.C) {
	p := big.NewInt(int64(65537))
	poly := NewPoly(Zi(p, 4), Zi(p, 3), Zi(p, 2))
	c.Assert(poly.String(), gc.Equals, "2z^2 + 3z^1 + 4")
}

func (s *PolySuite) TestPolyEval(c *gc.C) {
	var poly *Poly
	var z *Zp
	p := big.NewInt(int64(97))
	// Constant
	poly = NewPoly(Zi(p, 5))
	z = poly.Eval(Zi(p, 8))
	c.Assert(z.Int64(), gc.Equals, int64(5))
	// Linear
	poly = NewPoly(Zi(p, 5), Zi(p, 3))
	z = poly.Eval(Zi(p, 8))
	c.Assert(z.Int64(), gc.Equals, int64(29))
	// Quadratic
	poly = NewPoly(Zi(p, 5), Zi(p, 3), Zi(p, 2))
	z = poly.Eval(Zi(p, 8))
	c.Assert(z.Int64(), gc.Equals, Zi(p, 157).Int64())
}

func (s *PolySuite) TestPolyMul(c *gc.C) {
	p := big.NewInt(int64(97))
	x := NewPoly(Zi(p, -6), Zi(p, 11), Zi(p, -6), Zi(p, 1))
	y := NewPoly(Zi(p, 2), Zi(p, 1))
	z := NewPolyP(p).Mul(x, y)
	c.Assert(len(z.coeff), gc.Equals, 5)
	c.Logf("z=%v", z)
	for i, v := range []int{85, 16, 96, 93, 1} {
		c.Assert(z.coeff[i].String(), gc.Equals, Zi(p, v).String())
	}
}

func (s *PolySuite) TestPolyAdd(c *gc.C) {
	p := big.NewInt(int64(97))
	// (x+1) + (x+2) = (2x+3)
	x := NewPoly(Zi(p, 1), Zi(p, 1))
	y := NewPoly(Zi(p, 2), Zi(p, 1))
	z := NewPolyP(p).Add(x, y)
	c.Assert(z.degree, gc.Equals, 1)
	c.Assert(z.coeff[0].Int64(), gc.Equals, int64(3))
	c.Assert(z.coeff[1].Int64(), gc.Equals, int64(2))
	// (2x+3) - (x+2) = (x+1)
	x = NewPoly(Zi(p, 3), Zi(p, 2))
	y = NewPoly(Zi(p, 2), Zi(p, 1))
	z = NewPolyP(p).Sub(x, y)
	c.Assert(z.degree, gc.Equals, 1)
	c.Assert(z.coeff[0].Int64(), gc.Equals, int64(1))
	c.Assert(z.coeff[1].Int64(), gc.Equals, int64(1))
	// (x+1) - (x^2+2x+1) = (-x^2 - x)
	x = NewPoly(Zi(p, 1), Zi(p, 1))
	y = NewPoly(Zi(p, 1), Zi(p, 2), Zi(p, 1))
	z = NewPolyP(p).Sub(x, y)
	c.Assert(z.degree, gc.Equals, 2)
	c.Assert(z.coeff[0].Int64(), gc.Equals, int64(0))
	c.Assert(z.coeff[1].Int64(), gc.Equals, Zi(p, -1).Int64())
	c.Assert(z.coeff[2].Int64(), gc.Equals, Zi(p, -1).Int64())
}

func (s *PolySuite) TestPolyDivmod(c *gc.C) {
	// (x^2 + 2x + 1) / (x + 1) = (x + 1)
	p := big.NewInt(int64(97))
	x := NewPoly(Zi(p, 1), Zi(p, 2), Zi(p, 1))
	y := NewPoly(Zi(p, 1), Zi(p, 1))
	q, r, err := PolyDivmod(x, y)
	c.Logf("q=(%v) r=(%v) err=(%v)", q, r, err)
	c.Assert(q.degree, gc.Equals, 1)
	c.Assert(q.coeff[0].Int64(), gc.Equals, int64(1))
	c.Assert(q.coeff[1].Int64(), gc.Equals, int64(1))
	c.Assert(len(q.coeff), gc.Equals, 2)
	c.Assert(err, gc.IsNil, gc.Commentf("%v", err))
	c.Assert(r.degree, gc.Equals, 0)
	c.Assert(err, gc.IsNil)
}

func (s *PolySuite) TestGcd(c *gc.C) {
	p := big.NewInt(int64(97))
	x := NewPoly(Zi(p, 1), Zi(p, 2), Zi(p, 1))
	y := NewPoly(Zi(p, 1), Zi(p, 1))
	r, err := PolyGcd(x, y)
	c.Assert(err, gc.IsNil)
	c.Logf("r=(%v)", r)
	c.Assert(r.degree, gc.Equals, 1)
	c.Assert(r.coeff[0].Int64(), gc.Equals, int64(1))
	c.Assert(r.coeff[1].Int64(), gc.Equals, int64(1))
	c.Assert(len(r.coeff), gc.Equals, 2)
}
