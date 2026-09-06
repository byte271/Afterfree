"""Mark distributions as platform-specific: this package loads native code."""

from setuptools import Distribution, setup


class NativeDistribution(Distribution):
    def has_ext_modules(self):
        return True


setup(distclass=NativeDistribution)
