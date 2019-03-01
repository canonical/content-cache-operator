import shutil
import tempfile
import unittest


class TestCDN(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_test(self):
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
