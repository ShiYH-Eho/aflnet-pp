#!/usr/bin/env python3
"""LLM client used by ``utils/AI-agent/pro-template``.

``utils/AI-agent/statevar`` already ships a dependency-free client for any
OpenAI-compatible ``POST {base_url}/chat/completions`` endpoint (OpenAI, Azure
OpenAI, vLLM, Ollama, llama.cpp, LiteLLM, ...), so this module re-exports that
implementation instead of duplicating it.  Both tools live in the same tree and
must not drift apart.

The forwarding is lazy (PEP 562) on purpose: ``gen_templates.py --check`` and
``--from-answer`` are pure offline conversions and must keep working even when
the sibling directory is not around.

The endpoint is configured with the names every AI-agent tool uses:
``LLM_BASE_URL`` / ``LLM_API_KEY`` / ``LLM_MODEL`` (with ``OPENAI_*`` and
``AZURE_OPENAI_*`` as fallbacks), resolved by the shared client.
"""

from __future__ import print_function

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SHARED = os.path.abspath(os.path.join(HERE, os.pardir, 'statevar'))

_HINT = (
    'utils/AI-agent/pro-template reuses the chat client of utils/AI-agent/statevar, which is not '
    'present at %s.  Run the tool from an AFLNet++ checkout (or copy '
    'utils/AI-agent/statevar/llmclient.py next to it).' % SHARED
)


class _Unavailable(object):
    """Stand-in for a missing client; fails with a useful message when used."""

    def __init__(self, name):
        self._name = name

    def __call__(self, *args, **kwargs):
        raise RuntimeError(_HINT)

    def __getattr__(self, item):
        raise RuntimeError(_HINT)


def _load():
    """Load ``utils/AI-agent/statevar/llmclient.py`` by path.

    Importing by name would be ambiguous: when this directory is on
    ``sys.path`` (which is the case when ``gen_templates.py`` is run as a
    script) the name ``llmclient`` is already bound to *this* shim, so a plain
    ``import llmclient`` would hand the shim back to itself and every forwarded
    attribute access would recurse forever.  Loading the sibling file into a
    private module object keeps ``--check``/``--from-answer`` offline and the
    live path working at the same time.
    """

    path = os.path.join(SHARED, 'llmclient.py')
    if not os.path.isfile(path) or os.path.abspath(path) == os.path.abspath(__file__):
        return None
    try:
        import importlib.util
    except ImportError:  # pragma: no cover - Python 2, no tool there either
        return None
    try:
        spec = importlib.util.spec_from_file_location('_protemplate_statevar_client', path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules.setdefault(spec.name, module)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


_shared = _load()


def __getattr__(name):
    """Forward every public name to the shared implementation (PEP 562)."""
    if _shared is not None:
        return getattr(_shared, name)
    if name in ('ChatClient', 'LLMError', 'extract_json', 'env_first'):
        return _Unavailable(name)
    if name in ('DEFAULT_BASE_URL', 'DEFAULT_MODEL'):
        return {'DEFAULT_BASE_URL': 'https://api.deepseek.com',
                'DEFAULT_MODEL': 'deepseek-flash'}[name]
    raise AttributeError(name)


def available():
    """True when the shared client could be imported."""
    return _shared is not None


def hint():
    """Why the shared client is unreachable."""
    return _HINT
