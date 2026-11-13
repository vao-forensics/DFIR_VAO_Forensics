"""Send this process's Telegram Bot API calls through tg-i18n (services/tg_i18n) when TG_API_BASE is set.

About twenty call sites build https://api.telegram.org/bot<token>/<method> by hand; instead of touching
each one, urllib's opener rewrites that prefix. If tg-i18n cannot be reached the call goes straight to
Telegram (unchanged), so the bot never goes silent because of the translator. Imported once, early,
by app.py.
"""
import copy
import os
import urllib.error
import urllib.request

_PREFIX = 'https://api.telegram.org/'
_orig_open = urllib.request.OpenerDirector.open


def _routed_open(self, fullurl, data=None, timeout=None, *a, **kw):
    base = os.environ.get('TG_API_BASE', '').rstrip('/')
    url = fullurl.full_url if isinstance(fullurl, urllib.request.Request) else fullurl
    if base and isinstance(url, str) and url.startswith(_PREFIX):
        new = base + '/' + url[len(_PREFIX):]
        if isinstance(fullurl, urllib.request.Request):
            req = copy.copy(fullurl)
            req.full_url = new
        else:
            req = new
        try:
            if timeout is None:
                return _orig_open(self, req, data, *a, **kw)
            return _orig_open(self, req, data, timeout, *a, **kw)
        except urllib.error.HTTPError:
            raise                      # Telegram's own answer, relayed by tg-i18n
        except TimeoutError:
            raise                      # tg-i18n is working on it (translation): resending would duplicate
        except urllib.error.URLError as e:
            if isinstance(e.reason, TimeoutError):
                raise
            # refused / no such host: tg-i18n is down, go straight to Telegram
        except ConnectionError:
            pass
    if timeout is None:
        return _orig_open(self, fullurl, data, *a, **kw)
    return _orig_open(self, fullurl, data, timeout, *a, **kw)


if getattr(urllib.request.OpenerDirector.open, '__name__', '') != '_routed_open':
    urllib.request.OpenerDirector.open = _routed_open
