import sys

IS_PYTHON_2 = sys.version_info < (3,)
IS_PYTHON_3_6_OR_NEWER = sys.version_info >= (3, 6)
# see changes in pathlib.Path, slots are no more applied
# https://github.com/python/cpython/blob/ce121fd8755d4db9511ce4aab39d0577165e118e/Lib/pathlib.py#L952
IS_PYTHON_3_10_OR_NEWER = sys.version_info >= (3, 10)
# Pathlib.Path changed significantly in 3.12, so we will not need several
# parts of the code once python3.11 is no longer supported. This constant helps
# identifying those.
IS_PYTHON_3_12_OR_NEWER = sys.version_info >= (3, 12)
