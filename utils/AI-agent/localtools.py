#!/usr/bin/env python3
"""Sandboxed local workspace tools handed to the model by the AI-agent tools.

Both ``statevar/identify.py`` (which state variables the target implements) and
``corpus-enrich`` (message sequences that drive those variables) need details
that are not in the prompt: the constants a variable is compared against, the
handler that assigns it, the default in a config file.  The model therefore gets
three read-only tools over the target's working tree:

* ``list_dir``    -- directory inspection
* ``read_file``   -- a file with line numbers (a small line window at a time)
* ``search_text`` -- literal or regex search across the tree

Every path is resolved inside the workspace root; anything that escapes it
(``../``, an absolute path elsewhere, a symlink pointing out) is rejected with a
message the model can read and recover from.  The tools only read, only hand out
bounded excerpts, and never execute anything, so the agent stays a pure text
consumer of the tree the caller pointed it at.
"""

from __future__ import print_function

import fnmatch
import os
import re

DEFAULT_MAX_ENTRIES = 200
DEFAULT_MAX_FILE_LINES = 400
DEFAULT_MAX_SEARCH_RESULTS = 40
MAX_FILE_BYTES = 1 << 20
MAX_LINE_CHARS = 400
SKIP_DIRS = ('.git', '.svn', '.hg', '.bzr', '__pycache__', '.venv', 'venv',
             'node_modules', 'dist', 'build', '.mypy_cache', '.pytest_cache',
             '.cache', '.idea', '.vscode', 'CMakeFiles')

def tools_help(final_hint='{"action":"final","seed":{...}}'):
    """The tool help block; ``final_hint`` shows how that tool wants the answer."""
    return '''\
Available tools:
1. list_dir(path=".", max_entries=200)
2. read_file(path, start_line=1, end_line=%d)
3. search_text(query, include="**/*", is_regex=false, ignore_case=true, max_results=%d)

Tool call format -- answer with exactly one JSON object per turn:
{"action":"tool","tool":"read_file","args":{"path":"Source/ftpserv.c","start_line":200,"end_line":320}}
{"action":"tool","tool":"search_text","args":{"query":"MODE_PASSIVE","include":"*.c"}}
%s''' % (DEFAULT_MAX_FILE_LINES, DEFAULT_MAX_SEARCH_RESULTS, final_hint)


TOOLS_HELP = tools_help()


class Workspace(object):
    """Read-only view of ``root`` that the model may ask questions about."""

    def __init__(self, root, max_entries=DEFAULT_MAX_ENTRIES,
                 max_file_lines=DEFAULT_MAX_FILE_LINES,
                 max_search_results=DEFAULT_MAX_SEARCH_RESULTS):
        self.root = os.path.abspath(root)
        self.max_entries = max_entries
        self.max_file_lines = max_file_lines
        self.max_search_results = max_search_results

    # -- path handling -----------------------------------------------------

    def safe(self, path):
        """Absolute path inside the root, or ``ValueError``."""
        raw = str(path or '.').strip() or '.'
        if os.path.isabs(raw):
            candidate = os.path.realpath(raw)
        else:
            candidate = os.path.realpath(os.path.join(self.root, raw))
        root = os.path.realpath(self.root)
        if candidate != root and not candidate.startswith(root + os.sep):
            raise ValueError('path escapes the workspace root: %s' % path)
        return candidate

    def relative(self, path):
        rel = os.path.relpath(path, self.root)
        return '.' if rel == '.' else rel

    # -- tools -------------------------------------------------------------

    def list_dir(self, path='.', max_entries=None):
        directory = self.safe(path)
        if not os.path.exists(directory):
            return 'directory not found: %s' % path
        if not os.path.isdir(directory):
            return 'not a directory: %s' % path

        limit = int(max_entries or self.max_entries)
        entries = []
        try:
            names = sorted(os.listdir(directory),
                           key=lambda n: (not os.path.isdir(os.path.join(directory, n)),
                                          n.lower()))
        except OSError as exc:
            return 'cannot list %s: %s' % (path, exc)
        for name in names:
            suffix = '/' if os.path.isdir(os.path.join(directory, name)) else ''
            entries.append(name + suffix)
            if len(entries) >= limit:
                entries.append('... truncated after %d entries' % limit)
                break
        return 'Directory: %s\n%s' % (self.relative(directory), '\n'.join(entries))

    def read_file(self, path, start_line=1, end_line=None):
        if not path:
            return 'read_file needs a "path" argument'
        target = self.safe(path)
        if not os.path.exists(target):
            return 'file not found: %s' % path
        if not os.path.isfile(target):
            return 'not a file: %s' % path
        try:
            start = int(start_line)
            end = int(end_line) if end_line else start + self.max_file_lines - 1
        except (TypeError, ValueError):
            return 'start_line/end_line must be integers'
        if start < 1:
            return 'start_line must be >= 1'
        if end < start:
            return 'end_line must be >= start_line'
        if end - start + 1 > self.max_file_lines:
            end = start + self.max_file_lines - 1

        try:
            with open(target, 'r', errors='replace') as handle:
                lines = handle.read(MAX_FILE_BYTES).splitlines()
        except OSError as exc:
            return 'cannot read %s: %s' % (path, exc)

        body = []
        for index in range(start - 1, min(end, len(lines))):
            line = lines[index]
            if len(line) > MAX_LINE_CHARS:
                line = line[:MAX_LINE_CHARS] + '...'
            body.append('%5d: %s' % (index + 1, line))
        if not body:
            return 'File: %s (no lines in %d..%d, the file has %d line(s))' % (
                self.relative(target), start, end, len(lines))
        return 'File: %s\n%s' % (self.relative(target), '\n'.join(body))

    def search_text(self, query, include='**/*', is_regex=False,
                    ignore_case=True, max_results=None):
        if not query:
            return 'search_text needs a "query" argument'
        limit = int(max_results or self.max_search_results)
        pattern = None
        if is_regex:
            try:
                pattern = re.compile(query, re.IGNORECASE if ignore_case else 0)
            except re.error as exc:
                return 'invalid regular expression: %s' % exc
        needle = query.lower()
        include = include or '**/*'

        matches = []
        for current, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                full = os.path.join(current, name)
                rel = self.relative(full)
                if include not in ('**/*', '**') and not fnmatch.fnmatch(rel, include):
                    continue
                if self._looks_binary(full):
                    continue
                try:
                    with open(full, 'r', errors='replace') as handle:
                        lines = handle.read(MAX_FILE_BYTES).splitlines()
                except OSError:
                    continue
                for number, line in enumerate(lines, 1):
                    hit = pattern.search(line) if pattern else (needle in line.lower())
                    if not hit:
                        continue
                    text = line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + '...'
                    matches.append('%s:%d: %s' % (rel, number, text.strip()))
                    if len(matches) >= limit:
                        matches.append('... truncated after %d matches' % limit)
                        return 'Search results for: %s\n%s' % (query, '\n'.join(matches))
        if not matches:
            return 'Search results for: %s\nNo matches found' % query
        return 'Search results for: %s\n%s' % (query, '\n'.join(matches))

    @staticmethod
    def _looks_binary(path):
        try:
            with open(path, 'rb') as handle:
                return b'\0' in handle.read(4096)
        except OSError:
            return True

    # -- dispatch ----------------------------------------------------------

    def dispatch(self, tool, args):
        """Run one tool call; every problem is returned, never raised."""
        if not isinstance(args, dict):
            return 'tool arguments must be an object'
        tool = str(tool or '')
        try:
            if tool == 'list_dir':
                return self.list_dir(args.get('path', '.'),
                                     args.get('max_entries'))
            if tool == 'read_file':
                return self.read_file(args.get('path'), args.get('start_line', 1),
                                      args.get('end_line'))
            if tool == 'search_text':
                return self.search_text(args.get('query'), args.get('include', '**/*'),
                                        bool(args.get('is_regex', False)),
                                        bool(args.get('ignore_case', True)),
                                        args.get('max_results'))
        except ValueError as exc:
            return str(exc)
        except Exception as exc:  # a broken tool call must not kill the run
            return '%s failed: %s' % (tool or 'tool', exc)
        return 'unknown tool "%s"; %s' % (tool, TOOLS_HELP.splitlines()[0])
