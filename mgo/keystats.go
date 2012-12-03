package mgo

import (
	"flag"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	. "launchpad.net/hockeypuck"
	"time"
)

// Perform the key stat query overlapping this many
// time slices. For example, if we're updating the
// daily key counts and overlap=2, we'll always refresh
// yesterday's counts as well. This can't be less than 1.
// A number greater than 1 makes the rollups more resilient
// to downtime and race conditions at the expense of some
// redundant querying and updating.
const UPDATE_KEYSTATS_OVERLAP = 2

// Map key creation and modification times by the nearest hour
var mapKeysByHour = `function() {
	if (this.mtime > this.ctime) {
		emit(this.mtime - this.mtime % (3600000000000), { modified: 1, created: 0 });
	}
	emit(this.ctime - this.ctime % (3600000000000), { modified: 0, created: 1 });
};`

// Map key creation and modification times by the nearest day
var mapKeysByDay = `function() {
	if (this.mtime > this.ctime) {
		emit(this.mtime - this.mtime % (86400000000000), { modified: 1, created: 0 });
	}
	emit(this.ctime - this.ctime % (86400000000000), { modified: 0, created: 1 });
};`

// Reduce the created and modified counts for a given time slice key
var reduceTimeSlices = `function(key, values) {
	var result = { timestamp: key, created: 0, modified: 0 }
	values.forEach(function(value){
		result.modified += value.modified;
		result.created += value.created;
	});
	return result
};`

var UpdateKeyStats *bool = flag.Bool("update-keystats", false, "Update key statistics and exit.")

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
		q := coll.Find(bson.M{"value.timestamp": bson.M{"$gt": since.UnixNano()}})
		q = q.Sort("-timestamp")
		i := q.Iter()
		kos := new(struct{ Value *KeyOpStats })
		for i.Next(kos) {
			out <- kos.Value
		}
		err := i.Err()
		if err != nil {
			c.l.Println("Error querying key stats", err)
		}
		close(out)
	}()
	return out
}

func (c *MgoClient) UpdateKeysHourly(since time.Time) error {
	mr := &mgo.MapReduce{
		Map:    mapKeysByHour,
		Reduce: reduceTimeSlices,
		Out:    bson.M{"merge": "keysHourly"}}
	_, err := c.keys.Find(bson.M{"mtime": bson.M{"$gt": since.UnixNano()}}).MapReduce(mr, nil)
	return err
}

func (c *MgoClient) UpdateKeysDaily(since time.Time) error {
	mr := &mgo.MapReduce{
		Map:    mapKeysByDay,
		Reduce: reduceTimeSlices,
		Out:    bson.M{"merge": "keysDaily"}}
	_, err := c.keys.Find(bson.M{"mtime": bson.M{"$gt": since.UnixNano()}}).MapReduce(mr, nil)
	return err
}
