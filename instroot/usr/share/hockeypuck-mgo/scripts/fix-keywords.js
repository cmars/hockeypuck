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

/*
 * fix-keywords.js
 * ===============
 *
 * Fix keywords to improve search.
 * This script will repair UID keywords in a Hockeypuck MongoDB
 * prior to Hockeypuck 0.8.2, which fixed case-insensitive
 * search and improved keyword tokenization on load.
 * 
 * See also LP: #1108416
 */
conn = new Mongo();
db = conn.getDB("hockeypuck");
var c = db.keys.find()
while (c.hasNext()) {
	var key = c.next();
	try {
		var prevName = "";
		for (var i = 0; i < key.identities.length; i++) {
			var uid = key.identities[i]
			var newKeywords = [];
			var matches = uid.id.match(/(([^<()]+\s*)+\b)?\s*(\(([^()]+)\))?\s*(<([^>]+)>)?$/);
			var name = matches[1];
			var comment = matches[4];
			var email = matches[6];
			name = name.toLowerCase();
			email = email.toLowerCase();
			var fixName = [];
			name.split(/\W/).forEach(function(s){
				if (s.length > 2) {
					fixName[fixName.length] = s;
				}
			});
			name = fixName.join(" ");
			uid.keywords = [email];
			if (name != prevName) {
				uid.keywords[uid.keywords.length] = name;
				prevName = name;
			}
			print('id: ' + uid.id + ' keywords: ' + uid.keywords);
		}
		db.keys.save(key);
	} catch (err) {
		print("Exception processing key " + key.fingerprint + ": " + err);
	}
}
