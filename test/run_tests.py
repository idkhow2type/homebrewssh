import unittest
import sys
import os

# Add the project root to sys.path so tests can import from the source
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Discover all test files in the current directory
import test_trie
import test_stream_readers
import test_primitives
import test_packets
import test_integration
import test_crypto

def run_tests():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add tests from each module
    suite.addTests(loader.loadTestsFromModule(test_trie))
    suite.addTests(loader.loadTestsFromModule(test_stream_readers))
    suite.addTests(loader.loadTestsFromModule(test_primitives))
    suite.addTests(loader.loadTestsFromModule(test_packets))
    suite.addTests(loader.loadTestsFromModule(test_integration))
    suite.addTests(loader.loadTestsFromModule(test_crypto))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    if not result.wasSuccessful():
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
