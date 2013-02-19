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

var minKeywordLen = 3;

function keywordNormalize(str) {
	var fix = [];
	str.split(/\W/).forEach(function(s){
		if (s.length > 2) {
			fix[fix.length] = s;
		}
	});
	return fix.join(" ");
}

while (c.hasNext()) {
	var key = c.next();
	try {
		var kwSet = {};
		for (var i = 0; i < key.identities.length; i++) {
			var uid = key.identities[i]
			var newKeywords = [];
			var matches = uid.id.match(/^\s*(\S.*\b)?\s*(\([^(]+\))?\s*(<[^>]+>)?$/);
			var name = matches[1];
			if (matches[2] == undefined) {
				matches[2] = "";
			}
			if (matches[3] == undefined) {
				matches[3] = "";
			}
			var comment = matches[2].replace(/^\(|\)$/, '');
			var email = matches[3].replace(/^<|>$/, '');
			name = name.toLowerCase();
			comment = comment.toLowerCase();
			name = keywordNormalize(name);
			comment = keywordNormalize(comment);
			email = email.toLowerCase();
			uid.keywords = [];
			[name, comment, email].forEach(function(s){
				if (s.length > minKeywordLen && kwSet[s] == undefined) {
					uid.keywords[uid.keywords.length] = s;
					kwSet[s] = 1;
				}
			});
			print('id: ' + uid.id + ' keywords: ' + uid.keywords);
		}
		db.keys.save(key);
	} catch (err) {
		print("Exception processing key " + key.fingerprint + ": " + err);
	}
}
