package mgo

import (
	"flag"
	"time"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

// Perform the key stat query overlapping this many
// time slices. For example, if we're updating the
// daily key counts and overlap=2, we'll always refresh
// yesterday's counts as well. This can't be less than 1.
// A number greater than 1 makes the rollups more resilient
// to downtime and race conditions at the expense of some
// redundant querying and updating.
const UPDATE_QUERY_OVERLAP = 2

// Map key creation and modification times by the nearest hour
var mapKeysByHour = `function() {
	emit(this.mtime - this.mtime % (3600000000000), { modified: 1 });
	emit(this.ctime - this.ctime % (3600000000000), { created: 1 });
};`

// Map key creation and modification times by the nearest day
var mapKeysByDay = `function() {
	emit(this.mtime - this.mtime % (86400000000000), { modified: 1 });
	emit(this.ctime - this.ctime % (86400000000000), { created: 1 });
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

var updateKeyStats *bool = flag.Bool("rebuild-stats", false, "Rebuild key statistics and exit.")

func (c *MgoClient) UpdateKeysHourly() error {
	mr := &mgo.MapReduce{
		Map: mapKeysByHour,
		Reduce: reduceTimeSlices,
		Out: bson.M{"merge": "keys_hourly"}}
	since := time.Now().Add(time.Duration((0-UPDATE_QUERY_OVERLAP) * time.Hour))
	_, err := c.keys.Find(bson.M{"mtime": bson.M{"$gt": since}}).MapReduce(mr, nil)
	return err
}

func (c *MgoClient) UpdateKeysDaily() error {
	mr := &mgo.MapReduce{
		Map: mapKeysByDay,
		Reduce: reduceTimeSlices,
		Out: bson.M{"merge": "keys_daily"}}
	since := time.Now().Add(time.Duration((0-UPDATE_QUERY_OVERLAP)*24) * time.Hour)
	_, err := c.keys.Find(bson.M{"mtime": bson.M{"$gt": since}}).MapReduce(mr, nil)
	return err
}
