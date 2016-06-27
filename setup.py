#!/usr/bin/env python

import os
import sys

from subprocess import Popen


# Build modules documentation
if "install" in sys.argv and os.environ.get('READTHEDOCS'):
    proc = Popen(['make', 'modules'], cwd='docs/')
    (_, err) = proc.communicate()
    return_code = proc.wait()

    if return_code or err:
        raise Exception('Failed to generate doc: %s' % err)
