import unittest

from livepatch_repo.rpmver import evr_cmp, rpmvercmp


class TestRpmVersionComparison(unittest.TestCase):
    def test_numeric_release_segments_are_numeric(self) -> None:
        self.assertLess(rpmvercmp("687.9.1.el9_8", "687.10.1.el9_8"), 0)

    def test_epoch_precedes_version_and_release(self) -> None:
        self.assertGreater(evr_cmp("1", "1", "1", "0", "999", "999"), 0)

    def test_tilde_sorts_before_release(self) -> None:
        self.assertLess(rpmvercmp("1.0~rc1", "1.0"), 0)

    def test_equal_values(self) -> None:
        self.assertEqual(rpmvercmp("687.25.1.el9_8", "687.25.1.el9_8"), 0)


if __name__ == "__main__":
    unittest.main()
