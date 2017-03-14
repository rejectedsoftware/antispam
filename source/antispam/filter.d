/** Basic filter type definitions.

	Copyright: © 2013-2017 RejectedSoftware e.K.
	License: Subject to the terms of the General Public License version 3, as written in the included LICENSE.txt file.
	Authors: Sönke Ludwig
*/
module antispam.filter;

import vibe.data.json : Json;
import vibe.inet.message : InetHeaderMap;


/**
	Base interface for all spam filters.
*/
interface SpamFilter {
@safe:

	/// Unique string identifier for the filter type
	@property string id() const;

	/// Applies the given JSON settings object (filter specific format).
	void applySettings(Json settings);

	/// Returns a JSON object that contains all filter specific settings.
	Json getSettings() const;

	/// Performs immediate spam detection.
	SpamAction determineImmediateSpamStatus(in ref AntispamMessage);

	/// Performs I/O heavy spam detection (e.g. using an external web service)
	SpamAction determineAsyncSpamStatus(in ref AntispamMessage);

	/// Clears any learned classification information.
	void resetClassification();

	/// Manually classifies a message as spam/ham to feed learning routines.
	void classify(in ref AntispamMessage art, bool spam, bool unclassify = false);
}


/**
	Determins what to do with a certain message.
*/
enum SpamAction {
	amnesty, /// Accept message no matter what later filters may decide
	pass,    /// Do not block the message, but let other filers decide
	revoke,  /// Message is spam and should be revoked/hidden after being posted
	block,   /// Message is spam and should be blocked/deleted before being posted
}

struct AntispamMessage {
	InetHeaderMap headers;
	const(ubyte)[] message;
	const(string)[] peerAddress; // list of hops starting from the original client
}
