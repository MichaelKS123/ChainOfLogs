#!/usr/bin/env python3
"""
ChainOfLogs - Zero-Day Vulnerability Fuzzer
Created by Michael Semera

Advanced fuzzing tool for discovering security vulnerabilities
Supports mutation-based fuzzing, crash analysis, and GDB integration
"""

import os
import sys
import subprocess
import random
import struct
import time
import signal
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import re

class ChainOfLogsFuzzer:
    """
    Main fuzzer class implementing mutation-based fuzzing
    with crash detection and analysis
    """
    
    def __init__(self, target_binary: str, output_dir: str = "fuzzing_output"):
        """
        Initialize the fuzzer
        
        Args:
            target_binary: Path to the binary to fuzz
            output_dir: Directory for outputs and crash reports
        """
        self.target_binary = target_binary
        self.output_dir = output_dir
        self.crashes_dir = os.path.join(output_dir, "crashes")
        self.corpus_dir = os.path.join(output_dir, "corpus")
        self.reports_dir = os.path.join(output_dir, "reports")
        
        # Statistics
        self.stats = {
            'total_executions': 0,
            'crashes': 0,
            'unique_crashes': 0,
            'timeouts': 0,
            'hangs': 0,
            'start_time': None,
            'mutations_generated': 0
        }
        
        # Crash tracking
        self.crash_hashes = set()
        self.crash_details = []
        
        # Configuration
        self.timeout = 5  # seconds
        self.max_input_size = 10000
        self.mutation_rounds = 1000
        
        self._setup_directories()
        self._print_banner()
    
    def _setup_directories(self):
        """Create necessary directories"""
        for directory in [self.output_dir, self.crashes_dir, 
                         self.corpus_dir, self.reports_dir]:
            os.makedirs(directory, exist_ok=True)
    
    def _print_banner(self):
        """Print the fuzzer banner"""
        print("=" * 70)
        print("        🔗 CHAINOFLOGS - Zero-Day Vulnerability Fuzzer 🔗")
        print("                   Created by Michael Semera")
        print("=" * 70)
        print(f"\n📂 Target Binary: {self.target_binary}")
        print(f"📁 Output Directory: {self.output_dir}")
        print(f"⏱️  Timeout: {self.timeout}s")
        print(f"🎲 Max Input Size: {self.max_input_size} bytes")
        print("=" * 70 + "\n")
    
    def generate_seed_corpus(self, count: int = 10) -> List[bytes]:
        """
        Generate initial seed corpus for fuzzing
        
        Args:
            count: Number of seed inputs to generate
            
        Returns:
            List of seed byte strings
        """
        print(f"🌱 Generating {count} seed inputs...")
        
        seeds = []
        
        # 1. Empty input
        seeds.append(b'')
        
        # 2. Single characters
        for char in [b'A', b'0', b'\x00', b'\xff']:
            seeds.append(char)
        
        # 3. Common strings
        common_strings = [
            b'test',
            b'admin',
            b'root',
            b'../../etc/passwd',
            b'<script>alert(1)</script>',
            b'SELECT * FROM users',
            b'%s%s%s%s',
            b'AAAA' * 100,
        ]
        seeds.extend(common_strings)
        
        # 4. Binary patterns
        seeds.append(b'\x00' * 100)
        seeds.append(b'\xff' * 100)
        seeds.append(b'\x41' * 1000)
        
        # 5. Format strings
        seeds.append(b'%n' * 100)
        seeds.append(b'%x' * 100)
        
        # 6. Long strings
        seeds.append(b'A' * 10000)
        
        # Save to corpus
        for i, seed in enumerate(seeds[:count]):
            seed_path = os.path.join(self.corpus_dir, f"seed_{i:04d}")
            with open(seed_path, 'wb') as f:
                f.write(seed)
        
        print(f"✅ Generated {len(seeds[:count])} seed inputs\n")
        return seeds[:count]
    
    def mutate_input(self, data: bytes) -> bytes:
        """
        Apply random mutations to input data
        
        Mutation strategies:
        - Bit flips
        - Byte flips
        - Known integers
        - Block insertion/deletion
        - Arithmetic operations
        
        Args:
            data: Original input bytes
            
        Returns:
            Mutated input bytes
        """
        if len(data) == 0:
            return b'A' * random.randint(1, 100)
        
        mutation_type = random.randint(0, 10)
        data = bytearray(data)
        
        # Mutation 1: Bit flip
        if mutation_type == 0:
            if len(data) > 0:
                pos = random.randint(0, len(data) - 1)
                bit = random.randint(0, 7)
                data[pos] ^= (1 << bit)
        
        # Mutation 2: Byte flip
        elif mutation_type == 1:
            if len(data) > 0:
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.randint(0, 255)
        
        # Mutation 3: Insert interesting integer
        elif mutation_type == 2:
            interesting_ints = [0, 1, -1, 127, 128, 255, 256, 
                              32767, 32768, 65535, 65536,
                              0x7fffffff, 0x80000000, 0xffffffff]
            value = random.choice(interesting_ints)
            pos = random.randint(0, len(data))
            
            # Pack as different sizes
            pack_format = random.choice(['<B', '<H', '<I', '<Q'])
            try:
                packed = struct.pack(pack_format, value & ((1 << struct.calcsize(pack_format) * 8) - 1))
                data[pos:pos] = packed
            except:
                pass
        
        # Mutation 4: Insert block
        elif mutation_type == 3:
            block_size = random.randint(1, 100)
            block = bytes([random.randint(0, 255) for _ in range(block_size)])
            pos = random.randint(0, len(data))
            data[pos:pos] = block
        
        # Mutation 5: Delete block
        elif mutation_type == 4:
            if len(data) > 10:
                start = random.randint(0, len(data) - 10)
                length = random.randint(1, min(10, len(data) - start))
                del data[start:start + length]
        
        # Mutation 6: Duplicate block
        elif mutation_type == 5:
            if len(data) > 10:
                start = random.randint(0, len(data) - 10)
                length = random.randint(1, min(10, len(data) - start))
                block = data[start:start + length]
                pos = random.randint(0, len(data))
                data[pos:pos] = block
        
        # Mutation 7: Arithmetic increment
        elif mutation_type == 6:
            if len(data) > 0:
                pos = random.randint(0, len(data) - 1)
                data[pos] = (data[pos] + random.randint(1, 35)) % 256
        
        # Mutation 8: Arithmetic decrement
        elif mutation_type == 7:
            if len(data) > 0:
                pos = random.randint(0, len(data) - 1)
                data[pos] = (data[pos] - random.randint(1, 35)) % 256
        
        # Mutation 9: Known strings insertion
        elif mutation_type == 8:
            known_strings = [
                b'../../../',
                b'%n%n%n%n',
                b'<script>',
                b'SELECT * FROM',
                b'AAAA',
                b'\x00\x00\x00\x00',
                b'\xff\xff\xff\xff',
            ]
            string = random.choice(known_strings)
            pos = random.randint(0, len(data))
            data[pos:pos] = string
        
        # Mutation 10: Shuffle bytes
        elif mutation_type == 9:
            if len(data) > 2:
                start = random.randint(0, len(data) - 2)
                length = min(random.randint(2, 10), len(data) - start)
                block = list(data[start:start + length])
                random.shuffle(block)
                data[start:start + length] = block
        
        # Mutation 11: Repeat pattern
        else:
            if len(data) > 0:
                pattern_length = min(random.randint(1, 10), len(data))
                pattern = bytes(data[:pattern_length])
                repeat_count = random.randint(2, 100)
                data = bytearray(pattern * repeat_count)
        
        # Limit size
        if len(data) > self.max_input_size:
            data = data[:self.max_input_size]
        
        self.stats['mutations_generated'] += 1
        return bytes(data)
    
    def execute_target(self, input_data: bytes) -> Tuple[int, str, float]:
        """
        Execute target binary with input data
        
        Args:
            input_data: Input to feed to the target
            
        Returns:
            Tuple of (return_code, output, execution_time)
        """
        self.stats['total_executions'] += 1
        
        # Create temporary input file
        input_file = os.path.join(self.output_dir, f"input_{self.stats['total_executions']}.tmp")
        with open(input_file, 'wb') as f:
            f.write(input_data)
        
        try:
            start_time = time.time()
            
            # Execute with timeout
            process = subprocess.Popen(
                [self.target_binary, input_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
            
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
                execution_time = time.time() - start_time
                returncode = process.returncode
                output = stdout + stderr
                
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                execution_time = self.timeout
                returncode = -999  # Timeout indicator
                output = b"TIMEOUT"
                self.stats['timeouts'] += 1
            
        except Exception as e:
            returncode = -1
            output = str(e).encode()
            execution_time = 0
        
        finally:
            # Cleanup
            try:
                os.remove(input_file)
            except:
                pass
        
        return returncode, output.decode('utf-8', errors='ignore'), execution_time
    
    def analyze_crash(self, input_data: bytes, returncode: int, output: str) -> Optional[Dict]:
        """
        Analyze a crash to determine if it's unique
        
        Args:
            input_data: Input that caused the crash
            returncode: Return code from execution
            output: Output from the crashed process
            
        Returns:
            Crash details dictionary or None if not unique
        """
        # Create crash signature
        crash_signature = f"{returncode}_{hashlib.md5(output.encode()).hexdigest()[:8]}"
        crash_hash = hashlib.sha256(crash_signature.encode()).hexdigest()
        
        # Check if unique
        if crash_hash in self.crash_hashes:
            return None
        
        self.crash_hashes.add(crash_hash)
        self.stats['unique_crashes'] += 1
        
        # Determine crash type
        crash_type = "UNKNOWN"
        if returncode == -11 or "Segmentation fault" in output:
            crash_type = "SEGFAULT"
        elif returncode == -6 or "Aborted" in output:
            crash_type = "ABORT"
        elif returncode == -9:
            crash_type = "KILLED"
        elif returncode == -999:
            crash_type = "TIMEOUT"
        elif "stack" in output.lower():
            crash_type = "STACK_OVERFLOW"
        elif "heap" in output.lower():
            crash_type = "HEAP_CORRUPTION"
        
        crash_details = {
            'crash_id': crash_hash[:8],
            'timestamp': datetime.now().isoformat(),
            'crash_type': crash_type,
            'return_code': returncode,
            'crash_signature': crash_signature,
            'input_size': len(input_data),
            'output_snippet': output[:500] if output else "No output"
        }
        
        # Save crash input
        crash_file = os.path.join(self.crashes_dir, f"crash_{crash_hash[:8]}.bin")
        with open(crash_file, 'wb') as f:
            f.write(input_data)
        
        # Save crash report
        report_file = os.path.join(self.reports_dir, f"crash_{crash_hash[:8]}.json")
        with open(report_file, 'w') as f:
            json.dump(crash_details, f, indent=2)
        
        self.crash_details.append(crash_details)
        
        return crash_details
    
    def run_with_gdb(self, input_data: bytes) -> str:
        """
        Run crashed input under GDB for detailed analysis
        
        Args:
            input_data: Input that caused crash
            
        Returns:
            GDB output with backtrace and registers
        """
        input_file = os.path.join(self.output_dir, "gdb_input.tmp")
        with open(input_file, 'wb') as f:
            f.write(input_data)
        
        # GDB commands
        gdb_commands = f"""
set pagination off
run {input_file}
backtrace
info registers
quit
"""
        
        gdb_script = os.path.join(self.output_dir, "gdb_commands.txt")
        with open(gdb_script, 'w') as f:
            f.write(gdb_commands)
        
        try:
            result = subprocess.run(
                ['gdb', '-batch', '-x', gdb_script, self.target_binary],
                capture_output=True,
                timeout=self.timeout * 2,
                text=True
            )
            
            output = result.stdout + result.stderr
            
            # Cleanup
            os.remove(input_file)
            os.remove(gdb_script)
            
            return output
            
        except Exception as e:
            return f"GDB analysis failed: {str(e)}"
    
    def fuzz(self, iterations: int = 1000):
        """
        Main fuzzing loop
        
        Args:
            iterations: Number of fuzzing iterations
        """
        print(f"🚀 Starting fuzzing campaign ({iterations} iterations)...\n")
        self.stats['start_time'] = datetime.now()
        
        # Generate seed corpus
        corpus = self.generate_seed_corpus()
        
        print("🔄 Fuzzing in progress...")
        print("-" * 70)
        
        for i in range(iterations):
            # Select random seed
            seed = random.choice(corpus)
            
            # Mutate
            mutated_input = self.mutate_input(seed)
            
            # Execute
            returncode, output, exec_time = self.execute_target(mutated_input)
            
            # Check for crashes
            is_crash = returncode < 0 or returncode > 128
            
            if is_crash:
                self.stats['crashes'] += 1
                crash_details = self.analyze_crash(mutated_input, returncode, output)
                
                if crash_details:
                    print(f"\n🔥 CRASH FOUND! [{crash_details['crash_type']}]")
                    print(f"   Crash ID: {crash_details['crash_id']}")
                    print(f"   Return Code: {returncode}")
                    print(f"   Input Size: {len(mutated_input)} bytes")
                    
                    # Run GDB analysis if available
                    if self._check_gdb_available():
                        print(f"   🔍 Running GDB analysis...")
                        gdb_output = self.run_with_gdb(mutated_input)
                        
                        # Save GDB report
                        gdb_file = os.path.join(
                            self.reports_dir, 
                            f"gdb_{crash_details['crash_id']}.txt"
                        )
                        with open(gdb_file, 'w') as f:
                            f.write(gdb_output)
                        
                        # Extract key info
                        if "SIGSEGV" in gdb_output:
                            print(f"   💥 Segmentation fault detected")
                        if "0x" in gdb_output:
                            # Try to find crash address
                            addr_match = re.search(r'0x[0-9a-fA-F]+', gdb_output)
                            if addr_match:
                                print(f"   📍 Crash address: {addr_match.group()}")
                    
                    print("-" * 70)
            
            # Progress update every 100 iterations
            if (i + 1) % 100 == 0:
                self._print_progress(i + 1, iterations)
            
            # Add successful inputs to corpus
            if not is_crash and len(corpus) < 100:
                corpus.append(mutated_input)
        
        print("\n" + "=" * 70)
        print("✅ Fuzzing campaign completed!")
        self._print_final_stats()
    
    def _check_gdb_available(self) -> bool:
        """Check if GDB is available"""
        try:
            subprocess.run(['gdb', '--version'], 
                         capture_output=True, 
                         timeout=1)
            return True
        except:
            return False
    
    def _print_progress(self, current: int, total: int):
        """Print fuzzing progress"""
        elapsed = (datetime.now() - self.stats['start_time']).total_seconds()
        execs_per_sec = current / elapsed if elapsed > 0 else 0
        
        print(f"\n📊 Progress: {current}/{total} "
              f"({current/total*100:.1f}%)")
        print(f"   Executions/sec: {execs_per_sec:.2f}")
        print(f"   Total crashes: {self.stats['crashes']}")
        print(f"   Unique crashes: {self.stats['unique_crashes']}")
        print(f"   Timeouts: {self.stats['timeouts']}")
        print("-" * 70)
    
    def _print_final_stats(self):
        """Print final fuzzing statistics"""
        elapsed = (datetime.now() - self.stats['start_time']).total_seconds()
        
        print("\n📈 FINAL STATISTICS")
        print("=" * 70)
        print(f"⏱️  Total time: {elapsed:.2f} seconds")
        print(f"🔄 Total executions: {self.stats['total_executions']:,}")
        print(f"⚡ Executions/sec: {self.stats['total_executions']/elapsed:.2f}")
        print(f"🧬 Mutations generated: {self.stats['mutations_generated']:,}")
        print(f"💥 Total crashes: {self.stats['crashes']}")
        print(f"🎯 Unique crashes: {self.stats['unique_crashes']}")
        print(f"⏰ Timeouts: {self.stats['timeouts']}")
        print("=" * 70)
        
        if self.crash_details:
            print("\n🔥 CRASH SUMMARY")
            print("=" * 70)
            for crash in self.crash_details:
                print(f"\n📌 Crash ID: {crash['crash_id']}")
                print(f"   Type: {crash['crash_type']}")
                print(f"   Return Code: {crash['return_code']}")
                print(f"   Input Size: {crash['input_size']} bytes")
                print(f"   Time: {crash['timestamp']}")
            print("=" * 70)
        
        print(f"\n📁 Results saved to: {self.output_dir}")
        print(f"   Crashes: {self.crashes_dir}")
        print(f"   Reports: {self.reports_dir}")
        print("\n" + "=" * 70)


def create_vulnerable_test_program():
    """Create a simple vulnerable C program for testing"""
    
    vulnerable_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        printf("Error opening file\\n");
        return 1;
    }
    
    char buffer[100];
    
    // Vulnerability: No bounds checking
    while (fgets(buffer, 1000, fp)) {  // Buffer overflow!
        printf("Read: %s", buffer);
    }
    
    fclose(fp);
    return 0;
}
"""
    
    # Save to file
    with open("vulnerable_test.c", "w") as f:
        f.write(vulnerable_code)
    
    # Compile
    print("🔨 Compiling vulnerable test program...")
    compile_result = subprocess.run(
        ['gcc', '-o', 'vulnerable_test', 'vulnerable_test.c', '-no-pie', '-fno-stack-protector'],
        capture_output=True
    )
    
    if compile_result.returncode == 0:
        print("✅ Test program compiled: vulnerable_test")
        return True
    else:
        print("❌ Compilation failed")
        print(compile_result.stderr.decode())
        return False


def main():
    """Main execution function"""
    
    print("=" * 70)
    print("        🔗 CHAINOFLOGS - Zero-Day Vulnerability Fuzzer 🔗")
    print("                   Created by Michael Semera")
    print("=" * 70)
    
    # Check if target binary provided
    if len(sys.argv) < 2:
        print("\n❓ No target binary provided.")
        print("   Would you like to create a vulnerable test program? (y/n): ", end="")
        
        response = input().strip().lower()
        if response == 'y':
            if create_vulnerable_test_program():
                target = "./vulnerable_test"
            else:
                print("\n❌ Could not create test program. Exiting.")
                sys.exit(1)
        else:
            print("\nUsage: python chainoflogs_fuzzer.py <target_binary>")
            print("Example: python chainoflogs_fuzzer.py ./vulnerable_program")
            sys.exit(1)
    else:
        target = sys.argv[1]
    
    # Verify target exists
    if not os.path.exists(target):
        print(f"\n❌ Error: Target binary '{target}' not found!")
        sys.exit(1)
    
    # Create fuzzer instance
    fuzzer = ChainOfLogsFuzzer(target)
    
    # Get number of iterations
    print("\n🎲 Enter number of fuzzing iterations (default: 1000): ", end="")
    try:
        iterations_input = input().strip()
        iterations = int(iterations_input) if iterations_input else 1000
    except:
        iterations = 1000
    
    print(f"\n🚀 Starting fuzzing with {iterations} iterations...")
    print("   Press Ctrl+C to stop early\n")
    
    try:
        # Run fuzzer
        fuzzer.fuzz(iterations=iterations)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Fuzzing interrupted by user")
        fuzzer._print_final_stats()
    
    except Exception as e:
        print(f"\n❌ Error during fuzzing: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n✨ ChainOfLogs fuzzer finished!")
    print("   Created by Michael Semera\n")


if __name__ == "__main__":
    main()