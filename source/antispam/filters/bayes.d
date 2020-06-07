/**
	Word based bayes spam filter.

	Copyright: © 2013-2017 RejectedSoftware e.K.
	License: Subject to the terms of the General Public License version 3, as written in the included LICENSE.txt file.
	Authors: Sönke Ludwig
*/
module antispam.filters.bayes;

import antispam.filter;

import std.datetime;
import std.math;
import std.range;
import std.uni;
import vibe.core.core;
import vibe.core.file;
import vibe.core.log;
import vibe.data.json;
import vibe.inet.message;
import vibe.stream.operations;


class BayesSpamFilter : SpamFilter {
@safe:

	enum wordsFileName = "bayes-words.json";

	struct Word {
		long spamCount;
		long hamCount;
	}
	private {
		Word[string] m_words;
		long m_spamCount, m_hamCount;
		Timer m_updateTimer;
		bool m_writingWords = false;
		size_t m_maxWordLength = 64;
	}

	this()
	{
		try {
			() @trusted { // for vibe.d < 0.8.0
				auto f = openFile(wordsFileName);
				scope(exit) f.close();
				m_words = deserializeJson!(Word[string])(f.readAllUTF8());
			} ();
		} catch (Exception e) {
			logWarn("Failed to read bayes word file: %s", e.msg);
		}

		foreach (w; m_words) {
			m_spamCount += w.spamCount;
			m_hamCount += w.hamCount;
		}

		() @trusted { // for vibe.d < 0.8.0
			m_updateTimer =	createTimer(&writeWordFile!());
		} ();
	}

	@property string id() const { return "bayes"; }

	void applySettings(Json settings) {}

	Json getSettings() const { return Json(null); }

	SpamAction determineImmediateSpamStatus(in ref AntispamMessage art)
	{
		import vibe.core.log;
		double plsum = 0;

		long count = 0;
		logDiagnostic("Determining spam status");
		auto bias = 1 / cast(double)(m_spamCount + m_hamCount + 1);
		iterateWords(art, m_maxWordLength, (w) {
			if (auto pc = w in m_words) {
				auto p_w_s = (pc.spamCount + bias) / cast(double)m_spamCount;
				auto p_w_h = (pc.hamCount + bias) / cast(double)m_hamCount;
				auto prob = p_w_s / (p_w_s + p_w_h);
				plsum += std.math.log(1 - prob) - std.math.log(prob);
				logDiagnostic("%s: %s (%s vs. %s)", w, prob, pc.spamCount, pc.hamCount);
				count++;
			} else logDiagnostic("%s: unknown word", w);
		});
		auto prob = 1 / (1 + exp(plsum));
		logDiagnostic("---- final probability %s (%s)", prob, plsum);
		return prob > 0.75 ? SpamAction.revoke : SpamAction.pass;
	}

	SpamAction determineAsyncSpamStatus(ref const AntispamMessage)
	{
		return SpamAction.pass;
	}

	void resetClassification()
	{
		m_words = null;
		updateDB();
	}

	void classify(in ref AntispamMessage art, bool spam, bool unclassify = false)
	{
		import std.stdio : stderr, writefln;

		iterateWords(art, m_maxWordLength, (w) {
			auto cnt = m_words.get(w, Word(0, 0));
			if (unclassify) {
				if (spam) {
					if (cnt.spamCount > 0) cnt.spamCount--;
					else debug { () @trusted { stderr.writefln("Warning: Unclassifying unknown spam word: %s", w); } (); }
				} else {
					if (cnt.spamCount > 0) cnt.hamCount--;
					else debug { () @trusted { stderr.writefln("Warning: Unclassifying unknown ham word: %s", w); } (); }
				}
			} else {
				if (spam) cnt.spamCount++;
				else cnt.hamCount++;
			}
			m_words[w] = cnt;
		});
		if (unclassify) {
			if (spam) m_spamCount--;
			else m_hamCount--;
		} else {
			if (spam) m_spamCount++;
			else m_hamCount++;
		}
		updateDB();
	}

	private static void iterateWords(in ref AntispamMessage art, size_t max_word_length, scope void delegate(string) @safe del)
	{
		bool[string] seen;
		auto msg = () @trusted { return decodeMessage(art.message, art.headers.get("Content-Transfer-Encoding", "")); } ();
		auto subj = () @trusted { return art.headers["Subject"].decodeEncodedWords(); } ();
		iterateWords(msg, max_word_length, del, seen);
		iterateWords(subj, max_word_length, del, seen);
	}

	private static void iterateWords(string str, size_t max_word_length, scope void delegate(string) @safe del, ref bool[string] seen)
	{
		void handleWord(string word)
		{
			if (word !in seen && word.walkLength <= max_word_length) {
				seen[word] = true;
				del(word);
			}
		}

		bool inword = false;
		string wordstart;
		while (!str.empty) {
			auto ch = str.front;
			auto isword = ch.isAlpha() || ch.isNumber();
			if (inword && !isword) {
				handleWord(wordstart[0 .. wordstart.length - str.length]);
				inword = false;
			} else if (!inword && isword) {
				wordstart = str;
				inword = true;
			}
			str.popFront();
		}
		if (inword && wordstart.length) handleWord(wordstart);
	}

	private void updateDB()()
	{
		scope (failure) assert(false);
		() @trusted { m_updateTimer.rearm(1.seconds); } ();
	}

	private void writeWordFile()()
	{
		import vibe.stream.wrapper;

		if (m_writingWords) {
			updateDB();
			return;
		}
		m_writingWords = true;
		scope(exit) m_writingWords = false;

		try () @trusted { // for vibe.d < 0.8.0
			auto f = openFile(wordsFileName~".tmp", FileMode.createTrunc);
			static if (is(typeof(streamOutputRange(f))))
				auto rng = streamOutputRange(f);
			else auto rng = StreamOutputRange(f);
			serializeToJson(() @trusted { return &rng; } (), m_words);
			rng.flush();
			f.close();
			if (existsFile(wordsFileName)) removeFile(wordsFileName);
			moveFile(wordsFileName~".tmp", wordsFileName);
		} ();
		catch (Exception e) {
			logWarn("Failed to save Bayes words file.");
		}
	}
}

unittest {
	import std.conv : to;

	void test(string str, string[] words...) {
		string[] res;
		bool[string] seen;
		BayesSpamFilter.iterateWords(str, 10, (w) { res ~= w; }, seen);
		assert(res == words, res.to!string);
		foreach (w; res)
			assert(w in seen);
	}

	test("Hello, world", "Hello", "world");
	test("в займ, рекомендуем", "в", "займ");
	test("в займ, рекоме", "в", "займ", "рекоме");
}
