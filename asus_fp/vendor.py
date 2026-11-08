"""Import shim for the vendored goodix-fp-dump modules (third_party/goodix_fp_dump), which use
plain top-level imports of each other (``import goodix``, ``import protocol``)."""
import importlib
import os
import sys

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "third_party", "goodix_fp_dump")
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

protocol = importlib.import_module("protocol")
goodix = importlib.import_module("goodix")
tool = importlib.import_module("tool")
c52 = importlib.import_module("constants_52xd")

# goodix-fp-dump prints every command; silence it unless ASUS_FP_DEBUG is set
if not os.environ.get("ASUS_FP_DEBUG"):
    import builtins

    def _quiet_print(*a, **k):
        pass
    goodix.print = _quiet_print          # module-level name lookup -> no output
    protocol.print = _quiet_print
    del builtins
