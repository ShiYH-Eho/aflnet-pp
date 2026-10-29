#!/usr/bin/env python3
"""One small JSON tool-using LLM agent, shared by the AI-agent tools.

The three tools of ``utils/AI-agent`` ask a model for different things -- which
state variables the target implements (``statevar``), which client request types
a protocol has and what their messages look like (``pro-template``), and which
message sequences reach those states (``corpus-enrich``) -- but the interaction
is the same, and it is the one of ChatState's ``ai-agent/query.py``:

  * the model answers with exactly one JSON object per turn,
  * ``{"action":"tool","tool":"read_file","args":{...}}`` asks for a local read
    (``localtools.py`` hands it a sandboxed workspace),
  * ``{"action":"final", ...}`` -- or, because models often skip the wrapper, any
    other JSON object/list that is not a tool call -- is the final answer,
  * the tool results are fed back until that final answer arrives.

This module owns that loop, the turn parser and the default system prompt; a tool
only supplies its task prompt, a client (anything with ``chat(system, user)``)
and, when it has one, a workspace.
"""

from __future__ import print_function

import json
import re

DEFAULT_MAX_STEPS = 64


class AgentError(RuntimeError):
    """The endpoint (or its reply) failed; the caller decides what to do."""


SYSTEM_PROMPT = """\
You are a concise source-code analysis agent.
Your job is to complete the user's analysis task by inspecting the workspace with the available tools.
Think step by step internally, but output only a single JSON object on each turn.
Do not wrap JSON in markdown fences.
If you need more evidence, ask for a tool call. Prefer small, targeted reads.
When you are confident, return the final answer in JSON.
%s"""


def build_system_prompt(tools_help=None):
    """The query.py-style agent prompt, with the tool help appended."""
    return SYSTEM_PROMPT % (('\n' + tools_help) if tools_help else '')


def one_line(text, width=200):
    text = re.sub(r'\s+', ' ', (text or '')).strip()
    return text if len(text) <= width else text[:width - 3] + '...'


def fenced_block(text):
    match = re.search(r'```[A-Za-z0-9_+-]*\s*\n(.*?)```', text or '', re.S)
    return match.group(1) if match else None


def parse_turn(text):
    """The outermost JSON value a turn answers with, ``None`` when there is none."""
    if not text:
        return None
    block = fenced_block(text)
    decoder = json.JSONDecoder()
    for blob in ([block] if block else []) + [text]:
        for index, char in enumerate(blob):
            if char not in '{[':
                continue
            try:
                value, _end = decoder.raw_decode(blob[index:])
            except ValueError:
                continue
            if isinstance(value, (dict, list)):
                return value
    return None


def default_is_final(payload):
    """Anything that is not a tool call is the answer."""
    if isinstance(payload, list):
        return True
    if not isinstance(payload, dict):
        return False
    return str(payload.get('action') or '').lower() != 'tool'


def _is_tool_call(payload):
    if not isinstance(payload, dict):
        return False
    action = str(payload.get('action') or '').lower()
    if action == 'tool':
        return True
    # a model that drops the action but keeps the tool/args pair
    return action != 'final' and 'tool' in payload and 'args' in payload


class Agent(object):
    """Drive one model through a JSON tool loop.

    ``client`` is any object with ``chat(system, user) -> str``; ``workspace`` is
    a :class:`localtools.Workspace` (``None`` makes the agent single-shot: tool
    calls are answered with "no tools available" instead of a read).
    """

    def __init__(self, client, workspace=None, max_steps=DEFAULT_MAX_STEPS,
                 verbose=False, log=None, warnings=None):
        self.client = client
        self.workspace = workspace
        self.max_steps = max(1, int(max_steps))
        self.verbose = verbose
        self.log = log
        self.warnings = warnings
        self.tool_calls = 0

    def run(self, system, user, is_final=None,
            final_hint='{"action":"final","answer":{...}}'):
        """Run one conversation; return ``(payload, raw_text, tool_calls)``.

        ``payload`` is ``None`` when the model produced no final answer within
        ``max_steps`` turns (a warning is appended).  ``is_final`` overrides the
        default "anything but a tool call" rule for tasks whose answer has a
        shape worth checking.
        """
        accept = is_final or default_is_final
        transcript = []
        last = ''
        calls = 0
        for _step in range(self.max_steps):
            if not transcript:
                prompt = user
            else:
                prompt = ('%s\n\n=== conversation so far ===\n%s\n\n=== your turn ===\n'
                          'Answer with the next single JSON object.'
                          % (user, '\n'.join(transcript)))
            try:
                last = self.client.chat(system, prompt)
            except Exception as exc:      # the client's own failure type
                raise AgentError('endpoint failure: %s' % exc)
            payload = parse_turn(last)
            if _is_tool_call(payload):
                if self.workspace is None:
                    transcript.append('system: no workspace tools are available for '
                                      'this task; answer with the final JSON object.')
                    continue
                calls += 1
                self.tool_calls += 1
                result = self.workspace.dispatch(payload.get('tool'),
                                                 payload.get('args'))
                if self.verbose and self.log is not None:
                    self.log('[~]   %s -> %s'
                             % (payload.get('tool'), one_line(result, 100)))
                transcript.append('assistant: %s'
                                  % json.dumps(payload, ensure_ascii=False))
                transcript.append('tool result for %s(%s):\n%s'
                                  % (payload.get('tool'),
                                     json.dumps(payload.get('args') or {},
                                                ensure_ascii=False),
                                     result))
                continue
            if accept(payload):
                return payload, last, calls
            transcript.append('assistant: %s' % one_line(last, 400))
            transcript.append('system: that was not a usable answer.  Reply with '
                              'exactly one JSON object: {"action":"tool",...} to '
                              'inspect a file, or %s with the final answer.'
                              % final_hint)
        if self.warnings is not None:
            self.warnings.append('the model gave no final answer within %d step(s)'
                                 % self.max_steps)
        return None, last, calls
