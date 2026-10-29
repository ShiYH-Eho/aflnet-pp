#!/usr/bin/env python3
"""Minimal OpenAI-compatible chat client built on the standard library.

``utils/AI-agent/statevar`` must run on a bare AFLNet++ image where nothing is installed
from PyPI, so this module speaks HTTP through :mod:`urllib` instead of depending
on the ``openai`` package.  Any server that implements
``POST {base_url}/chat/completions`` works: OpenAI, Azure OpenAI, vLLM,
Ollama (``/v1``), llama.cpp's server, LiteLLM, ...

Configuration is read from the command line first, then from the environment.
Every tool in ``utils/AI-agent`` uses the same names:

    LLM_BASE_URL   (or OPENAI_BASE_URL / AZURE_OPENAI_BASE_URL)
    LLM_API_KEY    (or OPENAI_API_KEY / AZURE_OPENAI_API_KEY)
    LLM_MODEL      (or OPENAI_MODEL)       default deepseek-flash
"""

from __future__ import print_function

import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

DEFAULT_BASE_URL = 'https://api.deepseek.com'
DEFAULT_MODEL = 'deepseek-flash'

#: Environment variables every AI-agent tool reads, in priority order.
ENV_BASE_URL = ('LLM_BASE_URL', 'OPENAI_BASE_URL', 'AZURE_OPENAI_BASE_URL')
ENV_API_KEY = ('LLM_API_KEY', 'OPENAI_API_KEY', 'AZURE_OPENAI_API_KEY')
ENV_MODEL = ('LLM_MODEL', 'OPENAI_MODEL')


class LLMError(RuntimeError):
    """Raised when the endpoint cannot be reached or refuses the request."""


def env_first(*names):
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return None


def resolve_base_url(cli_value=None):
    return (cli_value or env_first(*ENV_BASE_URL)
            or DEFAULT_BASE_URL).rstrip('/')


def resolve_api_key(cli_value=None):
    return cli_value or env_first(*ENV_API_KEY)


def resolve_model(cli_value=None):
    return cli_value or env_first(*ENV_MODEL) or DEFAULT_MODEL


class ChatClient(object):
    """Tiny blocking chat-completions client."""

    def __init__(self, model=None, base_url=None, api_key=None, timeout=120,
                 retries=2, temperature=0.0, json_mode=False, max_tokens=None,
                 verbose=False):
        self.model = resolve_model(model)
        self.base_url = resolve_base_url(base_url)
        self.api_key = resolve_api_key(api_key)
        self.timeout = timeout
        self.retries = retries
        self.temperature = temperature
        self.json_mode = json_mode
        self.max_tokens = max_tokens
        self.verbose = verbose

    # -- low level ---------------------------------------------------------

    def _endpoint(self):
        if self.base_url.endswith('/chat/completions'):
            return self.base_url
        return self.base_url + '/chat/completions'

    def _headers(self):
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json',
                   'User-Agent': 'aflnet-pp-statevar/1.0'}
        if self.api_key:
            headers['Authorization'] = 'Bearer ' + self.api_key
        return headers

    def chat(self, system, user, json_mode=None):
        """Send one exchange and return the assistant message content."""
        if json_mode is None:
            json_mode = self.json_mode
        payload = {
            'model': self.model,
            'temperature': self.temperature,
            'messages': [{'role': 'system', 'content': system},
                         {'role': 'user', 'content': user}],
        }
        if self.max_tokens:
            payload['max_tokens'] = self.max_tokens
        if json_mode:
            payload['response_format'] = {'type': 'json_object'}

        body = json.dumps(payload).encode('utf-8')
        last = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(self._endpoint(), data=body,
                                         headers=self._headers(), method='POST')
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode('utf-8', 'replace')
                return self._parse_response(raw)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode('utf-8', 'replace')[:400]
                # A server that does not know response_format must not kill the run.
                if exc.code == 400 and json_mode:
                    if self.verbose:
                        print('[!] %s rejected response_format, retrying without it'
                              % self.base_url, file=sys.stderr)
                    json_mode = False
                    payload.pop('response_format', None)
                    body = json.dumps(payload).encode('utf-8')
                    continue
                last = LLMError('HTTP %d from %s: %s' % (exc.code, self._endpoint(), detail))
                if exc.code not in (408, 409, 425, 429, 500, 502, 503, 504, 529):
                    break
            except (urllib.error.URLError, ssl.SSLError, OSError, TimeoutError) as exc:
                last = LLMError('%s: %s' % (type(exc).__name__, exc))
            if attempt < self.retries:
                delay = min(2 ** attempt, 8)
                if self.verbose:
                    print('[!] %s -- retrying in %ds' % (last, delay), file=sys.stderr)
                time.sleep(delay)
        raise last or LLMError('request failed')

    @staticmethod
    def _parse_response(raw):
        try:
            data = json.loads(raw)
        except ValueError:
            raise LLMError('endpoint did not return JSON: %s' % raw[:200])
        if isinstance(data, dict) and data.get('error'):
            raise LLMError('endpoint error: %s' % str(data['error'])[:300])
        try:
            choices = data['choices']
            message = choices[0].get('message', {})
        except (KeyError, IndexError, TypeError):
            raise LLMError('unexpected response shape: %s' % raw[:200])
        content = message.get('content')
        if isinstance(content, list):  # some servers send content parts
            content = ''.join(part.get('text', '') for part in content
                              if isinstance(part, dict))
        if not content:
            raise LLMError('empty completion: %s' % raw[:200])
        return content


_FENCE_RE = re.compile(r'```(?:json|JSON)?\s*(.*?)```', re.S)


def extract_json(text):
    """Pull the first JSON array/object out of an LLM answer.

    Models happily wrap JSON in prose or code fences and occasionally emit a
    trailing comma, so this does the tolerant thing instead of failing the run.
    """
    if text is None:
        raise ValueError('no content to parse')
    candidates = [m.group(1) for m in _FENCE_RE.finditer(text)]
    candidates.append(text)
    for blob in candidates:
        blob = blob.strip()
        for opener, closer in (('[', ']'), ('{', '}')):
            start = blob.find(opener)
            if start == -1:
                continue
            depth = 0
            in_str = False
            escape = False
            for i in range(start, len(blob)):
                ch = blob[i]
                if in_str:
                    if escape:
                        escape = False
                    elif ch == '\\':
                        escape = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == opener:
                    depth += 1
                elif ch == closer:
                    depth -= 1
                    if depth == 0:
                        chunk = blob[start:i + 1]
                        for attempt in (chunk,
                                        re.sub(r',(\s*[}\]])', r'\1', chunk)):
                            try:
                                return json.loads(attempt)
                            except ValueError:
                                pass
                        break
    raise ValueError('no JSON found in the model answer')


def main(argv=None):
    """Trivial connectivity check: python3 llmclient.py 'prompt'."""
    import argparse
    ap = argparse.ArgumentParser(description='probe an OpenAI-compatible endpoint')
    ap.add_argument('prompt', nargs='?', default='Reply with the single word: pong')
    ap.add_argument('--model')
    ap.add_argument('--base-url')
    ap.add_argument('--api-key')
    ap.add_argument('--timeout', type=float, default=60)
    args = ap.parse_args(argv)

    client = ChatClient(model=args.model, base_url=args.base_url, api_key=args.api_key,
                        timeout=args.timeout, verbose=True)
    print('[~] POST %s (model=%s)' % (client._endpoint(), client.model), file=sys.stderr)
    print(client.chat('You are a terse assistant.', args.prompt))
    return 0


if __name__ == '__main__':
    sys.exit(main())
