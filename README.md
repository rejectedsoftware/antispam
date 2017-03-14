antispam
========

This library currently provides only very simple means to filter spam messages. It was broken out to a separate project so that it can be shared between different projects:

- [VibeNews](https://github.com/rejectedsoftware/vibenews) NTTP server and web forum
- [VibeLog](https://github.com/rejectedsoftware/vibelog) embeddable blog engine
- [Diskuto](https://github.com/rejectedsoftware/diskuto) embeddable comment engine


Example usage
-------------

	ìmport antispam.antispam;
	import vibe.data.json : parseJsonString;
	import std.algorithm.comparison : among;

	void main()
	{
		auto config = parseJsonString(
			`[
				{"filter": "bayes"},
				{"filter": "blacklist",
					"settings": {
						"ips": ["124.51.45.1", "41.23.11.5"]
					}
				}
			]`);

		auto antispam = new AntispamState;
		antispam.loadConfig(config);

		AntispamMessage msg;
		msg.headers["Subject"] = "8uy CH34P V14GR4!!11";
		msg.message = cast(const(ubyte)[])"Just look here: http://bestdrugdealz.c0m";
		msg.peerAddress = ["123.52.433.1", "vps12315.some.provider.n3t"];

		antispam.filterMessage!(
			(status) {
				if (status.among(SpamAction.revoke, SpamAction.block))
					throw new Exception("Your message has been rejected!");
				// otherwise store message...
			},
			(async_status) {
				if (async_status.among!(SpamAction.revoke, SpamAction.block)) {
					// Flag or delete the stored message.
				}
	
				// It could also theoretically happen here that async_status is amnesty
				// or pass, so that a message that was already rejected in the first
				// phase would be accepted in retrospective. You'll have to decides on
				// a per-application basis if it makes sense to support this case, or
				// if immediate rejections always have precedence.
			}
		)(msg);
	}
