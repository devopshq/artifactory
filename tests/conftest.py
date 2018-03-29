import os

import pytest


def pytest_collection_modifyitems(items):
    """
    Mark test - unit, integration or other. Idea from https://github.com/pypa/pip/blob/master/tests/conftest.py
    :param items:
    :return:
    """
    for item in items:
        if not hasattr(item, 'module'):  # e.g.: DoctestTextfile
            continue
        module_path = os.path.relpath(
            item.module.__file__,
            os.path.commonprefix([__file__, item.module.__file__]),
        )
        module_root_dir = module_path.split(os.pathsep)[0]
        if module_root_dir.startswith("integration"):
            item.add_marker(pytest.mark.integration)
        elif module_root_dir.startswith("unit"):
            item.add_marker(pytest.mark.unit)
        else:
            raise RuntimeError(
                "Unknown test type (filename = {})".format(module_path)
            )
