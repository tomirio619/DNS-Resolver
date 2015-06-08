__author__ = 'Tom Sandmann (s4330048) & Justin Mol (s4386094)'

# TODO : This
import Client
import Resolver
import unittest

class Test(unittest.TestCase):
    def test_ExistingHostClient(self):
        self.assertEqual("true", "false")

    def test_NotExistingHostClient(self):
        self.assertEqual("true", "false")

    def test_NoCacheSolveCorrectHost(self):
        self.assertEqual("true", "false")

    def test_NoCacheSolveFalseHost(self):
        self.assertEqual("true", "false")

    def test_NoCacheSolveCorrectHostThreaded(self):
        self.assertEqual("true", "false")

    def test_CacheNotCachedCachedCorrectHost(self):
        self.assertEqual("true", "false")

    def test_CacheSolveHostExpireTTL(self):
        self.assertEqual("true", "false")




