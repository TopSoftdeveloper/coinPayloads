from base64 import b64decode
import atexit
import builtins
import io
import os
import sys
import textwrap
import traceback

import _sitebuiltins

USER_BASE = None
USER_SITE = None
ENABLE_USER_SITE = None
PREFIXES = [sys.prefix, sys.exec_prefix]


def makepath(*paths):
    dir = os.path.join(*paths)
    try:
        dir = os.path.abspath(dir)
    except OSError:
        pass
    return dir, os.path.normcase(dir)


def abs_paths():
    """Set all module __file__ and __cached__ attributes to an absolute path"""
    for m in set(sys.modules.values()):
        if (getattr(getattr(m, '__loader__', None), '__module__', None) not in
                ('_frozen_importlib', '_frozen_importlib_external')):
            continue
        try:
            m.__file__ = os.path.abspath(m.__file__)
        except (AttributeError, OSError, TypeError):
            pass
        try:
            m.__cached__ = os.path.abspath(m.__cached__)
        except (AttributeError, OSError, TypeError):
            pass


def removeduppaths():
    """Remove duplicate entries from sys.path along with making them absolute"""
    L = []
    known_paths = set()
    for dir in sys.path:
        dir, dircase = makepath(dir)
        if dircase not in known_paths:
            L.append(dir)
            known_paths.add(dircase)
    sys.path[:] = L
    return known_paths


def _init_pathinfo():
    """Return a set containing all existing file system items from sys.path."""
    d = set()
    for item in sys.path:
        try:
            if os.path.exists(item):
                _, itemcase = makepath(item)
                d.add(itemcase)
        except TypeError:
            continue
    return d


def addpackage(sitedir, name, known_paths):
    """Process a .pth file within the site-packages directory"""
    if known_paths is None:
        known_paths = _init_pathinfo()
        reset = True
    else:
        reset = False
    fullname = os.path.join(sitedir, name)
    try:
        f = io.TextIOWrapper(io.open_code(fullname))
    except OSError:
        return
    with f:
        for n, line in enumerate(f):
            if line.startswith("#"):
                continue
            try:
                if line.startswith(("import ", "import\t")):
                    exec(line)
                    continue
                line = line.rstrip()
                dir, dircase = makepath(sitedir, line)
                if not dircase in known_paths and os.path.exists(dir):
                    sys.path.append(dir)
                    known_paths.add(dircase)
            except Exception:
                print("Error processing line {:d} of {}:\n".format(n+1, fullname), file=sys.stderr)
                for record in traceback.format_exception(*sys.exc_info()):
                    for line in record.splitlines():
                        print('  '+line, file=sys.stderr)
                print("\nRemainder of file ignored", file=sys.stderr)
                break
    if reset:
        known_paths = None
    return known_paths


def addsitedir(sitedir, known_paths=None):
    """Add 'sitedir' argument to sys.path if missing and handle .pth files in 'sitedir'"""
    if known_paths is None:
        known_paths = _init_pathinfo()
        reset = True
    else:
        reset = False
    sitedir, sitedircase = makepath(sitedir)
    if not sitedircase in known_paths:
        sys.path.append(sitedir)
        known_paths.add(sitedircase)
    try:
        names = os.listdir(sitedir)
    except OSError:
        return
    names = [name for name in names if name.endswith(".pth")]
    for name in sorted(names):
        addpackage(sitedir, name, known_paths)
    if reset:
        known_paths = None
    return known_paths


def check_enableusersite():
    """Check if user site directory is safe for inclusion"""
    if sys.flags.no_user_site:
        return False
    if hasattr(os, "getuid") and hasattr(os, "geteuid"):
        if os.geteuid() != os.getuid():
            return None
    if hasattr(os, "getgid") and hasattr(os, "getegid"):
        if os.getegid() != os.getgid():
            return None
    return True


def _getuserbase():
    env_base = os.environ.get("PYTHONUSERBASE", None)
    if env_base:
        return env_base

    def joinuser(*args):
        return os.path.expanduser(os.path.join(*args))

    if os.name == "nt":
        base = os.environ.get("APPDATA") or "~"
        return joinuser(base, "Python")
    if sys.platform == "darwin" and sys._framework:
        return joinuser("~", "Library", sys._framework, "%d.%d" % sys.version_info[:2])
    return joinuser("~", ".local")


def _get_path(userbase):
    version = sys.version_info
    if os.name == 'nt':
        return f'{userbase}\\Python{version[0]}{version[1]}\\site-packages'
    if sys.platform == 'darwin' and sys._framework:
        return f'{userbase}/lib/python/site-packages'
    return f'{userbase}/lib/python{version[0]}.{version[1]}/site-packages'


def getuserbase():
    """Returns the `user base` directory path."""
    global USER_BASE
    if USER_BASE is None:
        USER_BASE = _getuserbase()
    return USER_BASE


def getusersitepackages():
    """Returns the user-specific site-packages directory path."""
    global USER_SITE
    userbase = getuserbase()
    if USER_SITE is None:
        USER_SITE = _get_path(userbase)
    return USER_SITE


def addusersitepackages(known_paths):
    """Add a per user site-package to sys.path"""
    user_site = getusersitepackages()
    if ENABLE_USER_SITE and os.path.isdir(user_site):
        addsitedir(user_site, known_paths)
    return known_paths


def getsitepackages(prefixes=None):
    """Returns a list containing all global site-packages directories."""
    sitepackages = []
    seen = set()
    if prefixes is None:
        prefixes = PREFIXES
    for prefix in prefixes:
        if not prefix or prefix in seen:
            continue
        seen.add(prefix)
        if os.sep == '/':
            sitepackages.append(os.path.join(prefix, "lib", "python%d.%d" % sys.version_info[:2], "site-packages"))
        else:
            sitepackages.append(prefix)
            sitepackages.append(os.path.join(prefix, "lib", "site-packages"))
    return sitepackages


def addsitepackages(known_paths, prefixes=None):
    """Add site-packages to sys.path"""
    for sitedir in getsitepackages(prefixes):
        if os.path.isdir(sitedir):
            addsitedir(sitedir, known_paths)
    return known_paths


def setquit():
    """Define new builtins 'quit' and 'exit'."""
    if os.sep == '\\':
        eof = 'Ctrl-Z plus Return'
    else:
        eof = 'Ctrl-D (i.e. EOF)'
    builtins.quit = _sitebuiltins.Quitter('quit', eof)
    builtins.exit = _sitebuiltins.Quitter('exit', eof)


def setcopyright():
    """Set 'copyright' and 'credits' in builtins"""
    builtins.copyright = _sitebuiltins._Printer("copyright", sys.copyright)
    if sys.platform[:4] == 'java':
        builtins.credits = _sitebuiltins._Printer("credits", "Jython is maintained by the Jython developers (www.jython.org).")
    else:
        builtins.credits = _sitebuiltins._Printer("credits", """Thanks to CWI, CNRI, BeOpen.com, Zope Corporation and a cast of thousands for supporting Python development.  See www.python.org for more information.""")
    files, dirs = [], []
    if hasattr(os, '__file__'):
        here = os.path.dirname(os.__file__)
        files.extend(["LICENSE.txt", "LICENSE"])
        dirs.extend([os.path.join(here, os.pardir), here, os.curdir])
    builtins.license = _sitebuiltins._Printer("license", "See https://www.python.org/psf/license/", files, dirs)


def sethelper():
    builtins.help = _sitebuiltins._Helper()


def enablerlcompleter():
    """Enable default readline configuration on interactive prompts."""
    def register_readline():
        import atexit
        try:
            import readline
            import rlcompleter
        except ImportError:
            return
        readline_doc = getattr(readline, '__doc__', '')
        if readline_doc is not None and 'libedit' in readline_doc:
            readline.parse_and_bind('bind ^I rl_complete')
        else:
            readline.parse_and_bind('tab: complete')
        try:
            readline.read_init_file()
        except OSError:
            pass
        if readline.get_current_history_length() == 0:
            history = os.path.join(os.path.expanduser('~'), '.python_history')
            try:
                readline.read_history_file(history)
            except OSError:
                pass

            def write_history():
                try:
                    readline.write_history_file(history)
                except OSError:
                    pass
            atexit.register(write_history)
    sys.__interactivehook__ = register_readline


def venv(known_paths):
    global PREFIXES, ENABLE_USER_SITE
    env = os.environ
    if sys.platform == 'darwin' and '__PYVENV_LAUNCHER__' in env:
        executable = sys._base_executable = os.environ['__PYVENV_LAUNCHER__']
    else:
        executable = sys.executable
    exe_dir, _ = os.path.split(os.path.abspath(executable))
    site_prefix = os.path.dirname(exe_dir)
    sys._home = None
    conf_basename = 'pyvenv.cfg'
    candidate_confs = [conffile for conffile in (
        os.path.join(exe_dir, conf_basename),
        os.path.join(site_prefix, conf_basename)
    ) if os.path.isfile(conffile)]
    if candidate_confs:
        virtual_conf = candidate_confs[0]
        system_site = "true"
        with open(virtual_conf, encoding='utf-8') as f:
            for line in f:
                if '=' in line:
                    key, _, value = line.partition('=')
                    key = key.strip().lower()
                    value = value.strip()
                    if key == 'include-system-site-packages':
                        system_site = value.lower()
                    elif key == 'home':
                        sys._home = value
        sys.prefix = sys.exec_prefix = site_prefix
        addsitepackages(known_paths, [sys.prefix])
        if system_site == "true":
            PREFIXES.insert(0, sys.prefix)
        else:
            PREFIXES = [sys.prefix]
            ENABLE_USER_SITE = False
    return known_paths


def execsitecustomize():
    """Run custom site specific code, if available."""
    try:
        try:
            import sitecustomize
        except ImportError as exc:
            if exc.name == 'sitecustomize':
                pass
            else:
                raise
    except Exception as err:
        if sys.flags.verbose:
            sys.excepthook(*sys.exc_info())
        else:
            sys.stderr.write("Error in sitecustomize; set PYTHONVERBOSE for traceback:\n%s: %s\n" % (err.__class__.__name__, err))


def execusercustomize():
    """Run custom user specific code, if available."""
    try:
        try:
            import usercustomize
        except ImportError as exc:
            if exc.name == 'usercustomize':
                pass
            else:
                raise
    except Exception as err:
        if sys.flags.verbose:
            sys.excepthook(*sys.exc_info())
        else:
            sys.stderr.write("Error in usercustomize; set PYTHONVERBOSE for traceback:\n%s: %s\n" % (err.__class__.__name__, err))


def main():
    """Add standard site-specific directories to the module search path."""
    global ENABLE_USER_SITE
    orig_path = sys.path[:]
    known_paths = removeduppaths()
    if orig_path != sys.path:
        abs_paths()
    known_paths = venv(known_paths)
    if ENABLE_USER_SITE is None:
        ENABLE_USER_SITE = check_enableusersite()
    known_paths = addusersitepackages(known_paths)
    known_paths = addsitepackages(known_paths)
    setquit()
    setcopyright()
    sethelper()
    if not sys.flags.isolated:
        enablerlcompleter()
    execsitecustomize()
    if ENABLE_USER_SITE:
        execusercustomize()


def _script():
    help = """%s [--user-base] [--user-site]

Without arguments print some useful information
With arguments print the value of USER_BASE and/or USER_SITE separated by '%s'.

Exit codes with --user-base or --user-site:
  0 - user site directory is enabled
  1 - user site directory is disabled by user
  2 - uses site directory is disabled by super user or for security reasons
 >2 - unknown error
"""
    args = sys.argv[1:]
    if not args:
        user_base = getuserbase()
        user_site = getusersitepackages()
        print("sys.path = [")
        for dir in sys.path:
            print("    %r," % (dir,))
        print("]")
        print("USER_BASE: %r (%s)" % (user_base, "exists" if os.path.isdir(user_base) else "doesn't exist"))
        print("USER_SITE: %r (%s)" % (user_site, "exists" if os.path.isdir(user_site) else "doesn't exist"))
        print("ENABLE_USER_SITE: %r" % ENABLE_USER_SITE)
        sys.exit(0)
    buffer = []
    if '--user-base' in args:
        buffer.append(USER_BASE)
    if '--user-site' in args:
        buffer.append(USER_SITE)
    if buffer:
        print(os.pathsep.join(buffer))
        if ENABLE_USER_SITE:
            sys.exit(0)
        elif ENABLE_USER_SITE is False:
            sys.exit(1)
        elif ENABLE_USER_SITE is None:
            sys.exit(2)
        else:
            sys.exit(3)
    else:
        print(textwrap.dedent(help % (sys.argv[0], os.pathsep)))
        sys.exit(10)


if not sys.flags.no_site:
    main()


if __name__ == '__main__':
    _script()
