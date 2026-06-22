"""Test runner for comprehensive LLM Red Teaming platform testing."""

import subprocess
import sys
from pathlib import Path


def run_tests():
    """Run all comprehensive test suites."""
    test_files = [
        "tests/test_all_single_turn_scenarios.py",
        "tests/test_all_multi_turn_scenarios.py",
        "tests/test_all_vulnerability_types.py",
    ]
    
    results = {}
    project_root = Path(__file__).parent
    
    print("=" * 80)
    print("LLM RED TEAMING PLATFORM - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    print()
    
    for test_file in test_files:
        test_path = project_root / test_file
        if not test_path.exists():
            print(f"⚠️  Test file not found: {test_path}")
            continue
        
        print(f"Running: {test_file}")
        print("-" * 80)
        
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            str(test_path),
            "-v",
            "--tb=short",
            "-s",
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        results[test_file] = {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        
        print(result.stdout)
        if result.stderr:
            print(f"STDERR:\n{result.stderr}")
        print()
    
    # Print summary
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    for test_file, result in results.items():
        status = "✅ PASSED" if result["returncode"] == 0 else "❌ FAILED"
        print(f"{status}: {test_file}")
    
    all_passed = all(r["returncode"] == 0 for r in results.values())
    
    print()
    if all_passed:
        print("✅ ALL TESTS PASSED")
    else:
        print("❌ SOME TESTS FAILED")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(run_tests())
