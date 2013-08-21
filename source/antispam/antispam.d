module antispam.antispam;

import vibe.data.json;
import vibe.inet.message;


/**
	Base interface for all spam filters.
*/
interface SpamFilter {
	/// Unique string identifier for the filter type
	@property string id() const;

	/// Applies the given Json settings object (filter specific format).
	void applySettings(Json settings);

	/// Performs immediate spam detection.
	SpamAction determineImmediateSpamStatus(in ref Message);

	/// Performs I/O heavy spam detection (e.g. using an external web service)
	SpamAction determineAsyncSpamStatus(in ref Message);

	/// Clears any learned classification information.
	void resetClassification();

	/// Manually classifies a message as spam/ham to feed learning routines.
	void classify(in ref Message art, bool spam, bool unclassify = false);
}


/**
	Determins what to do with a certain message.
*/
enum SpamAction {
	pass,    /// Do not block the message
	revoke,  /// Message is spam and should be revoked/hidden after being posted
	block,   /// Message is spam and should be blocked/deleted before being posted
}

struct Message {
	InetHeaderMap headers;
	const(ubyte)[] message;
	string[] peerAddress; // list of hops starting from the original client
}