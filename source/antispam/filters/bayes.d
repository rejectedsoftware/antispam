/**
	Word based bayes spam filter.

	Copyright: © 2013 RejectedSoftware e.K.
	License: Subject to the terms of the General Public License version 3, as written in the included LICENSE.txt file.
	Authors: Sönke Ludwig
*/
module antispam.filters.bayes;

import antispam.antispam;

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
			auto f = openFile(wordsFileName);
			scope(exit) f.close();
			m_words = deserializeJson!(Word[string])(f.readAllUTF8());
		} catch (Exception e) {
			logWarn("Failed to read bayes word file: %s", e.msg);
		}

		foreach (w; m_words) {
			m_spamCount += w.spamCount;
			m_hamCount += w.hamCount;
		}

		m_updateTimer = createTimer(&writeWordFile);
	}

	@property string id() const { return "bayes"; }

	void applySettings(Json settings)
	{
	}

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
		iterateWords(art, m_maxWordLength, (w) {
			auto cnt = m_words.get(w, Word(0, 0));
			if (unclassify) {
				if (spam) {
					assert(cnt.spamCount > 0, "Unclassifying unknown spam word: "~w);
					cnt.spamCount--;
				} else {
					assert(cnt.hamCount > 0, "Unclassifying unknown ham word: "~w);
					cnt.hamCount--;
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

	private static void iterateWords(in ref AntispamMessage art, size_t max_word_length, scope void delegate(string) del)
	{
		bool[string] seen;
		iterateWords(decodeMessage(art.message, art.headers.get("Content-Transfer-Encoding", "")), max_word_length, del, seen);
		iterateWords(art.headers["Subject"].decodeEncodedWords(), max_word_length, del, seen);
	}

	private static void iterateWords(string str, size_t max_word_length, scope void delegate(string) del, ref bool[string] seen)
	{
		void handleWord(string word)
		{
			if (word !in seen && word.length <= max_word_length) {
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

	private void updateDB()
	{
		m_updateTimer.rearm(1.seconds);
	}

	private void writeWordFile()
	{
		import vibe.stream.wrapper;

		if (m_writingWords) {
			updateDB();
			return;
		}
		m_writingWords = true;
		scope(exit) m_writingWords = false;

		auto f = openFile(wordsFileName~".tmp", FileMode.createTrunc);
		auto str = StreamOutputRange(f);
		serializeToJson(&str, m_words);
		f.close();
		if (existsFile(wordsFileName)) removeFile(wordsFileName);
		moveFile(wordsFileName~".tmp", wordsFileName);
	}
}
