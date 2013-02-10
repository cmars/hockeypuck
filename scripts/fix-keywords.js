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
 * This script will update keywords in an existing
 * Hockeypuck MongoDB to support changes for
 * case-insensitive search, and improved keyword tokenization.
 * See also LP: #1108416
 */
conn = new Mongo();
db = conn.getDB("hockeypuck");
var c = db.keys.find()
while (c.hasNext()) {
	var key = c.next();
	for (var i = 0; i < key.identities.length; i++) {
		var id = key.identities[i]
		var newKeywords = {};
		id.keywords.forEach(function(kw){
			var parts = kw.split(/\s+|[<>()@,]+/)
			parts.forEach(function(part){
				if (part.length > 2) {
					part = part.toLowerCase();
					newKeywords[part] = 1;
				}
			});
		});
		id.keywords = Object.keySet(newKeywords);
		print('updated keywords:' + id.keywords)
	}
	db.keys.save(key);
}
