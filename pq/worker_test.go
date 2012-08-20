/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package pq

import (
	"fmt"
	"os/user"
	"testing"
	"github.com/bmizerany/assert"
)

func TestConnect(t *testing.T) {
	u, err := user.Current()
	assert.Equal(t, err, nil)
	worker, err := NewWorker(fmt.Sprintf("user=%s dbname=hkptest password=qazwsxedc sslmode=disable", u.Name))
	assert.Equal(t, err, nil)
	assert.T(t, worker != nil)
	_, err = worker.GetKey("ffffffff")
	assert.Equal(t, err, nil)
}
