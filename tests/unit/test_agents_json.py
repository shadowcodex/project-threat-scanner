"""Tests for thresher.agents._json — shared LLM-output extraction helpers."""

from __future__ import annotations

import json

from thresher.agents._json import extract_json_object, extract_stream_result

# ---------------------------------------------------------------------------
# extract_stream_result
# ---------------------------------------------------------------------------


class TestExtractStreamResult:
    def test_pulls_result_text_and_num_turns(self):
        raw = "\n".join(
            [
                json.dumps({"type": "system"}),
                json.dumps({"type": "assistant", "message": {"content": []}}),
                json.dumps({"type": "result", "result": "hello world", "num_turns": 3}),
            ]
        )
        text, turns = extract_stream_result(raw)
        assert text == "hello world"
        assert turns == 3

    def test_returns_zero_turns_when_no_result_line(self):
        raw = json.dumps({"type": "assistant", "message": {"content": []}})
        _text, turns = extract_stream_result(raw)
        assert turns == 0

    def test_falls_back_to_last_assistant_text_on_error(self):
        raw = "\n".join(
            [
                json.dumps(
                    {
                        "type": "assistant",
                        "message": {
                            "content": [{"type": "text", "text": "partial output"}],
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "result",
                        "result": "",
                        "is_error": True,
                        "subtype": "max_turns",
                        "num_turns": 10,
                    }
                ),
            ]
        )
        text, turns = extract_stream_result(raw)
        assert text == "partial output"
        assert turns == 10

    def test_returns_empty_when_error_and_no_fallback(self):
        raw = json.dumps(
            {
                "type": "result",
                "result": "",
                "is_error": True,
                "subtype": "max_turns",
            }
        )
        text, _turns = extract_stream_result(raw)
        assert text == ""

    def test_ignores_invalid_json_lines(self):
        raw = "\n".join(
            [
                "garbage line",
                json.dumps({"type": "result", "result": "ok", "num_turns": 1}),
                "more garbage",
            ]
        )
        text, turns = extract_stream_result(raw)
        assert text == "ok"
        assert turns == 1

    def test_returns_raw_when_no_result_line_and_no_assistant(self):
        raw = "just some text without stream-json structure"
        text, turns = extract_stream_result(raw)
        # Falls through to returning raw as-is
        assert text == raw
        assert turns == 0

    def test_stringifies_dict_result_value(self):
        """Some agent configs emit result as a dict; round-trip through json."""
        raw = json.dumps(
            {
                "type": "result",
                "result": {"hidden_dependencies": [], "summary": "ok"},
                "num_turns": 2,
            }
        )
        text, turns = extract_stream_result(raw)
        assert json.loads(text) == {"hidden_dependencies": [], "summary": "ok"}
        assert turns == 2


# ---------------------------------------------------------------------------
# extract_json_object
# ---------------------------------------------------------------------------


class TestExtractJsonObject:
    def test_direct_json_object(self):
        result = extract_json_object('{"a": 1, "b": 2}')
        assert result == {"a": 1, "b": 2}

    def test_unwraps_result_envelope(self):
        """If text is {'result': '<inner_json_str>'}, unwrap to inner."""
        inner = json.dumps({"hidden_dependencies": [], "summary": "ok"})
        outer = json.dumps({"result": inner})
        result = extract_json_object(outer, accept=lambda d: "hidden_dependencies" in d)
        assert result == {"hidden_dependencies": [], "summary": "ok"}

    def test_extracts_from_markdown_code_fence(self):
        text = 'Some prose here.\n```json\n{"x": 42}\n```\nmore prose'
        result = extract_json_object(text)
        assert result == {"x": 42}

    def test_extracts_from_unlabeled_code_fence(self):
        text = 'Output:\n```\n{"x": 42}\n```\n'
        result = extract_json_object(text)
        assert result == {"x": 42}

    def test_brace_scan_finds_object_in_prose(self):
        text = 'Here is the result: {"y": 7} done.'
        result = extract_json_object(text)
        assert result == {"y": 7}

    def test_brace_scan_handles_nested_braces(self):
        text = 'before {"a": {"b": 1}} after'
        result = extract_json_object(text)
        assert result == {"a": {"b": 1}}

    def test_returns_none_when_nothing_parseable(self):
        result = extract_json_object("no json here, just words")
        assert result is None

    def test_returns_none_for_empty_string(self):
        assert extract_json_object("") is None

    def test_accept_filters_candidates(self):
        """accept callback filters which dicts qualify."""
        text = '{"foo": 1}'
        result = extract_json_object(text, accept=lambda d: "bar" in d)
        assert result is None

    def test_accept_returns_first_passing_candidate(self):
        text = '{"hidden_dependencies": [], "summary": "ok"}'
        result = extract_json_object(text, accept=lambda d: "hidden_dependencies" in d)
        assert result == {"hidden_dependencies": [], "summary": "ok"}

    def test_prefers_inner_envelope_over_outer_when_filter_matches(self):
        """When both outer and unwrapped inner are dicts, the filter picks the right one."""
        inner = json.dumps({"hidden_dependencies": [], "summary": "ok"})
        outer = json.dumps({"result": inner})
        result = extract_json_object(outer, accept=lambda d: "hidden_dependencies" in d)
        assert "hidden_dependencies" in result

    def test_ignores_non_object_top_level(self):
        """Lists at top level are not returned."""
        result = extract_json_object("[1, 2, 3]")
        assert result is None
