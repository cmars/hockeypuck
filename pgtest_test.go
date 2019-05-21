package pgtest

import (
	"database/sql"
	"testing"

	_ "github.com/lib/pq"
	gc "gopkg.in/check.v1"
)

func Test(t *testing.T) { gc.TestingT(t) }

type S struct {
	PGSuite
}

var _ = gc.Suite(&S{})

func (s *S) TestRun(c *gc.C) {
	db, err := sql.Open("postgres", s.URL)
	c.Assert(err, gc.IsNil)
	var n int
	err = db.QueryRow("SELECT 1").Scan(&n)
	c.Assert(err, gc.IsNil)
	c.Assert(n, gc.Equals, 1, gc.Commentf("SELECT 1 = %d", n))
}
