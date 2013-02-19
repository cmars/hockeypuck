package mgo

import (
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	. "launchpad.net/hockeypuck"
	"log"
	"time"
)

func (c *MgoClient) KeyStatsHourly() chan *KeyOpStats {
	// Last 24 hours
	return c.keyStats(c.keysHourly, time.Now().Add(time.Duration(-24)*time.Hour))
}

func (c *MgoClient) KeyStatsDaily() chan *KeyOpStats {
	// Last 7 days
	return c.keyStats(c.keysDaily, time.Now().Add(time.Duration(-24*7)*time.Hour))
}

func (c *MgoClient) keyStats(coll *mgo.Collection, since time.Time) chan *KeyOpStats {
	out := make(chan *KeyOpStats)
	go func() {
		q := coll.Find(bson.M{"timestamp": bson.M{"$gt": since.UnixNano()}})
		q = q.Sort("-timestamp")
		i := q.Iter()
		for kos := new(KeyOpStats); i.Next(kos); kos = new(KeyOpStats) {
			out <- kos
		}
		err := i.Err()
		if err != nil {
			log.Println("Error querying key stats", err)
		}
		close(out)
	}()
	return out
}
