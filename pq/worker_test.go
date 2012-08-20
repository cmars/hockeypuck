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
