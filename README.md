# 🔗 ChainOfLogs - Zero-Day Vulnerability Fuzzer

**Created by Michael Semera**

ChainOfLogs is an advanced mutation-based fuzzer designed to discover security vulnerabilities and zero-day exploits in software. Features intelligent mutation strategies, crash analysis, GDB integration, and comprehensive reporting.

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is provided for educational and authorized security testing purposes ONLY.

- ✅ **Legal Use**: Security research, authorized penetration testing, your own software
- ❌ **Illegal Use**: Testing software without permission, malicious purposes
- 📝 Always obtain written permission before testing third-party software
- 🔒 The author is not responsible for misuse of this tool

**Use responsibly and ethically!**

---

## ✨ Features

### Fuzzing Capabilities
- 🧬 **Mutation-Based Fuzzing** - 11 different mutation strategies
- 🌱 **Seed Corpus Generation** - Automatic test case generation
- 🎯 **Intelligent Mutations** - Bit flips, byte operations, known integers
- 📊 **Coverage Analysis** - Track execution paths
- ⚡ **High Performance** - 100+ executions per second

### Crash Detection
- 💥 **Crash Detection** - Identifies segfaults, aborts, timeouts
- 🔍 **Unique Crash Tracking** - Deduplicates similar crashes
- 📋 **Crash Classification** - SEGFAULT, ABORT, TIMEOUT, etc.
- 💾 **Crash Reproduction** - Saves inputs that trigger crashes

### Analysis & Debugging
- 🔬 **GDB Integration** - Automatic debugging of crashes
- 📈 **Backtrace Analysis** - Stack trace extraction
- 🗺️ **Register Dumps** - CPU state at crash
- 📊 **Detailed Reports** - JSON crash reports

### Reporting
- 📝 **Real-time Statistics** - Execution rate, crash count
- 📁 **Organized Output** - Separate dirs for crashes, reports, corpus
- 📊 **Performance Metrics** - Executions/sec, mutation rate
- 🎨 **Color-coded Output** - Easy-to-read terminal output

---

## 🏗️ Architecture

### Fuzzing Pipeline

```
┌─────────────┐
│ Seed Corpus │
│   (Initial) │
└──────┬──────┘
       │
       ▼
┌─────────────┐      ┌──────────────┐
│  Mutation   │ ───► │   Execute    │
│   Engine    │      │    Target    │
└─────────────┘      └──────┬───────┘
       ▲                    │
       │                    ▼
       │             ┌──────────────┐
       │             │   Crashed?   │
       │             └──────┬───────┘
       │                    │
       │              Yes   │   No
       │             ┌──────┴──────┐
       │             ▼             ▼
       │      ┌─────────────┐  ┌──────────┐
       │      │   Analyze   │  │   Add    │
       │      │    Crash    │  │  Corpus  │
       │      └──────┬──────┘  └────┬─────┘
       │             │              │
       │             ▼              │
       │      ┌─────────────┐      │
       │      │  Run GDB    │      │
       │      │  Analysis   │      │
       │      └──────┬──────┘      │
       │             │              │
       │             ▼              │
       │      ┌─────────────┐      │
       └──────┤   Report    │◄─────┘
              └─────────────┘
```

### Mutation Strategies

**11 Mutation Types:**
1. **Bit Flip** - Flip random bits
2. **Byte Flip** - Replace random bytes
3. **Integer Injection** - Insert interesting integers (0, -1, MAX_INT, etc.)
4. **Block Insertion** - Add random byte sequences
5. **Block Deletion** - Remove byte sequences
6. **Block Duplication** - Copy and paste blocks
7. **Arithmetic Inc** - Increment bytes
8. **Arithmetic Dec** - Decrement bytes
9. **Known String Injection** - Insert "../../../", "%n", SQL queries
10. **Byte Shuffling** - Randomize byte order
11. **Pattern Repetition** - Repeat patterns

---

## 📋 Prerequisites

### Required Software
- **Python** 3.6 or higher
- **GCC** (for compiling test programs)
- **GDB** (for crash analysis - optional but recommended)

### Operating System
- Linux (recommended)
- macOS (supported)
- Windows (with WSL)

---

## 🚀 Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/chainoflogs.git
cd chainoflogs
```

### Step 2: Verify Python

```bash
python3 --version  # Should be 3.6+
```

### Step 3: Install GDB (Optional)

```bash
# Ubuntu/Debian
sudo apt-get install gdb

# macOS
brew install gdb

# Fedora/RHEL
sudo dnf install gdb
```

### Step 4: Make Executable

```bash
chmod +x chainoflogs_fuzzer.py
```

---

## 💻 Usage

### Basic Usage

```bash
# Fuzz a binary
python3 chainoflogs_fuzzer.py <target_binary>

# Example
python3 chainoflogs_fuzzer.py ./my_program
```

### Create Test Program

```bash
# The fuzzer can create a vulnerable test program
python3 chainoflogs_fuzzer.py
# Select 'y' when prompted to create test program
```

### With Custom Iterations

```bash
python3 chainoflogs_fuzzer.py ./target_binary
# Enter number of iterations when prompted (e.g., 10000)
```

### Command Line Help

```bash
python3 chainoflogs_fuzzer.py --help
```

---

## 📊 Example Session

```
══════════════════════════════════════════════════════════════════
        🔗 CHAINOFLOGS - Zero-Day Vulnerability Fuzzer 🔗
                   Created by Michael Semera
══════════════════════════════════════════════════════════════════

📂 Target Binary: ./vulnerable_test
📁 Output Directory: fuzzing_output
⏱️  Timeout: 5s
🎲 Max Input Size: 10000 bytes
══════════════════════════════════════════════════════════════════

🌱 Generating 10 seed inputs...
✅ Generated 10 seed inputs

🚀 Starting fuzzing campaign (1000 iterations)...

🔄 Fuzzing in progress...
──────────────────────────────────────────────────────────────────

🔥 CRASH FOUND! [SEGFAULT]
   Crash ID: a3f9b2c1
   Return Code: -11
   Input Size: 2048 bytes
   🔍 Running GDB analysis...
   💥 Segmentation fault detected
   📍 Crash address: 0x00007fffffffe000
──────────────────────────────────────────────────────────────────

📊 Progress: 100/1000 (10.0%)
   Executions/sec: 127.45
   Total crashes: 3
   Unique crashes: 2
   Timeouts: 1
──────────────────────────────────────────────────────────────────

✅ Fuzzing campaign completed!

📈 FINAL STATISTICS
══════════════════════════════════════════════════════════════════
⏱️  Total time: 7.85 seconds
🔄 Total executions: 1,000
⚡ Executions/sec: 127.39
🧬 Mutations generated: 1,000
💥 Total crashes: 5
🎯 Unique crashes: 3
⏰ Timeouts: 2
══════════════════════════════════════════════════════════════════

🔥 CRASH SUMMARY
══════════════════════════════════════════════════════════════════

📌 Crash ID: a3f9b2c1
   Type: SEGFAULT
   Return Code: -11
   Input Size: 2048 bytes
   Time: 2025-11-01T10:15:30

📌 Crash ID: b7e4d8a2
   Type: ABORT
   Return Code: -6
   Input Size: 5120 bytes
   Time: 2025-11-01T10:16:45
══════════════════════════════════════════════════════════════════

📁 Results saved to: fuzzing_output
   Crashes: fuzzing_output/crashes
   Reports: fuzzing_output/reports
```

---

## 📁 Output Structure

### Directory Layout

```
fuzzing_output/
├── crashes/
│   ├── crash_a3f9b2c1.bin    # Binary input that triggered crash
│   ├── crash_b7e4d8a2.bin
│   └── crash_c1f3e7d9.bin
├── corpus/
│   ├── seed_0000              # Initial seed inputs
│   ├── seed_0001
│   └── seed_0002
├── reports/
│   ├── crash_a3f9b2c1.json   # Detailed crash report (JSON)
│   ├── gdb_a3f9b2c1.txt      # GDB analysis output
│   ├── crash_b7e4d8a2.json
│   └── gdb_b7e4d8a2.txt
└── temp files...
```

### Crash Report Format (JSON)

```json
{
  "crash_id": "a3f9b2c1",
  "timestamp": "2025-11-01T10:15:30.123456",
  "crash_type": "SEGFAULT",
  "return_code": -11,
  "crash_signature": "-11_a3f9b2c1",
  "input_size": 2048,
  "output_snippet": "Segmentation fault (core dumped)"
}
```

---

## 🔬 GDB Integration

### Automatic Analysis

When a crash is detected, ChainOfLogs automatically runs GDB to extract:

1. **Backtrace** - Call stack at crash
2. **Register State** - CPU registers
3. **Crash Address** - Memory location
4. **Signal Information** - Type of crash (SIGSEGV, etc.)

### GDB Output Example

```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7a3d000 in ?? ()

#0  0x00007ffff7a3d000 in ?? ()
#1  0x0000000000401234 in vulnerable_function (buf=0x7fffffffe000) at test.c:15
#2  0x0000000000401156 in main (argc=2, argv=0x7fffffffe100) at test.c:25

Registers:
rax            0x7fffffffe000
rbx            0x0
rcx            0x7ffff7b04a37
rdx            0x7fffffffe000
rsi            0x7fffffffe000
rdi            0x7fffffffe000
rip            0x7ffff7a3d000
```

### Manual GDB Analysis

```bash
# Load crashed input in GDB
gdb ./target_binary

# At GDB prompt
(gdb) run fuzzing_output/crashes/crash_a3f9b2c1.bin
(gdb) backtrace
(gdb) info registers
(gdb) x/20x $rsp
```

---

## 🎯 Fuzzing Targets

### Good Targets for Fuzzing

**File Parsers:**
- Image decoders (PNG, JPEG, GIF)
- Document readers (PDF, DOCX)
- Archive handlers (ZIP, TAR, RAR)
- Audio/Video codecs (MP3, MP4, AVI)

**Network Protocols:**
- HTTP servers
- FTP clients
- SSH implementations
- DNS resolvers

**Data Formats:**
- XML/JSON parsers
- Database engines
- Compression algorithms
- Serialization libraries

**Command Line Tools:**
- Text processors
- File utilities
- Converters
- Compilers

### Creating a Test Target

```c
// vulnerable_example.c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    
    FILE *fp = fopen(argv[1], "r");
    if (!fp) return 1;
    
    char buffer[100];  // Small buffer
    
    // Vulnerability: No size check
    while (fgets(buffer, 1000, fp)) {  // Reads too much!
        printf("%s", buffer);
    }
    
    fclose(fp);
    return 0;
}
```

**Compile:**
```bash
# Disable protections for testing
gcc -o vulnerable_example vulnerable_example.c \
    -no-pie \
    -fno-stack-protector \
    -g
```

---

## 🐛 Vulnerability Classes Detected

### 1. Buffer Overflows
**Description:** Writing beyond allocated memory

**Detection:** SIGSEGV, SIGABRT

**Example:**
```c
char buf[10];
strcpy(buf, very_long_string);  // Overflow!
```

### 2. Stack Overflows
**Description:** Stack corruption via recursion or large allocations

**Detection:** Stack-related crashes

**Example:**
```c
void recursive() {
    char big_array[10000];
    recursive();  // Infinite recursion
}
```

### 3. Heap Corruption
**Description:** Invalid heap operations

**Detection:** malloc/free errors, SIGABRT

**Example:**
```c
char *ptr = malloc(10);
free(ptr);
free(ptr);  // Double free!
```

### 4. Null Pointer Dereference
**Description:** Accessing NULL pointers

**Detection:** SIGSEGV at address 0x0

**Example:**
```c
char *ptr = NULL;
*ptr = 'A';  // Crash!
```

### 5. Integer Overflows
**Description:** Arithmetic results exceed type limits

**Detection:** Incorrect behavior, possible crashes

**Example:**
```c
size_t size = INT_MAX + 1;  // Overflow
char *buf = malloc(size);   // Wrong size!
```

### 6. Format String Vulnerabilities
**Description:** User-controlled format strings

**Detection:** SIGSEGV, memory corruption

**Example:**
```c
printf(user_input);  // Should be printf("%s", user_input)
```

---

## 📊 Performance Tuning

### Increasing Speed

**1. Reduce Timeout:**
```python
fuzzer.timeout = 1  # Faster but may miss hangs
```

**2. Parallel Fuzzing:**
```bash
# Run multiple instances
python3 chainoflogs_fuzzer.py ./target &
python3 chainoflogs_fuzzer.py ./target &
python3 chainoflogs_fuzzer.py ./target &
```

**3. Limit Input Size:**
```python
fuzzer.max_input_size = 1000  # Smaller inputs = faster
```

### Improving Coverage

**1. Larger Seed Corpus:**
```python
corpus = fuzzer.generate_seed_corpus(count=100)
```

**2. More Iterations:**
```bash
# Run for longer
# Enter 100000 when prompted
```

**3. Diverse Seeds:**
```python
# Add real-world inputs to corpus
corpus.append(open('real_input.dat', 'rb').read())
```

---

## 🔍 Advanced Usage

### Custom Fuzzer Configuration

```python
from chainoflogs_fuzzer import ChainOfLogsFuzzer

# Create fuzzer
fuzzer = ChainOfLogsFuzzer(
    target_binary="./my_target",
    output_dir="custom_output"
)

# Customize settings
fuzzer.timeout = 10  # 10 second timeout
fuzzer.max_input_size = 50000  # 50KB max input
fuzzer.mutation_rounds = 5000  # More mutations

# Generate larger seed corpus
seeds = fuzzer.generate_seed_corpus(count=50)

# Run fuzzing
fuzzer.fuzz(iterations=10000)
```

### Analyzing Results

```python
# Load crash reports
import json

with open('fuzzing_output/reports/crash_a3f9b2c1.json') as f:
    crash = json.load(f)

print(f"Crash Type: {crash['crash_type']}")
print(f"Input Size: {crash['input_size']}")

# Load crash-triggering input
with open('fuzzing_output/crashes/crash_a3f9b2c1.bin', 'rb') as f:
    crash_input = f.read()

# Reproduce crash
import subprocess
subprocess.run(['./target', '/tmp/test_input'])
```

---

## 🛠️ Troubleshooting

### Issue: No Crashes Found

**Causes:**
- Target is well-written
- Insufficient iterations
- Target has protections enabled

**Solutions:**
```bash
# Run longer
python3 chainoflogs_fuzzer.py ./target
# Enter 100000+ iterations

# Compile target without protections
gcc -o target source.c -no-pie -fno-stack-protector -z execstack
```

### Issue: GDB Not Working

**Problem:** GDB analysis fails

**Solution:**
```bash
# Install GDB
sudo apt-get install gdb  # Ubuntu
brew install gdb          # macOS

# Check GDB works
gdb --version

# Disable ASLR (testing only!)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

### Issue: Too Many Timeouts

**Problem:** Target hangs frequently

**Solution:**
```python
# Increase timeout
fuzzer.timeout = 10  # 10 seconds

# Or detect hangs differently
# (implement custom hang detection)
```

### Issue: Permission Denied

**Problem:** Cannot execute target

**Solution:**
```bash
# Make target executable
chmod +x ./target_binary

# Check file exists
ls -la ./target_binary
```

---

## 🎓 Learning Resources

### Fuzzing Concepts
- **Mutation-based Fuzzing** - Random modifications to inputs
- **Coverage-guided Fuzzing** - Track code paths (AFL, LibFuzzer)
- **Taint Analysis** - Track data flow
- **Symbolic Execution** - Explore all paths

### Recommended Reading
- **"The Fuzzing Book"** - Comprehensive fuzzing guide
- **"Fuzzing: Breaking Things with Random Inputs"** - Michael Sutton
- **AFL Documentation** - American Fuzzy Lop fuzzer
- **OWASP Testing Guide** - Security testing methodologies

### Related Tools
- **AFL (American Fuzzy Lop)** - Coverage-guided fuzzer
- **LibFuzzer** - In-process fuzzer
- **Radamsa** - General-purpose test case generator
- **Peach Fuzzer** - Smart fuzzing platform
- **Honggfuzz** - Security-oriented fuzzer

---

## 🚀 Future Enhancements

### Planned Features
- [ ] **Coverage-Guided Fuzzing** - Track code coverage
- [ ] **Parallel Fuzzing** - Multi-process support
- [ ] **Network Fuzzing** - Fuzz network protocols
- [ ] **Grammar-Based Fuzzing** - Use input grammars
- [ ] **Sanitizer Integration** - AddressSanitizer, UBSan
- [ ] **Taint Analysis** - Track data propagation
- [ ] **Web Dashboard** - Real-time fuzzing monitor
- [ ] **Crash Triaging** - Automatic exploit analysis
- [ ] **AFL Integration** - Hybrid fuzzing mode
- [ ] **Docker Support** - Containerized fuzzing

---

## 🤝 Contributing

Contributions welcome!

1. Fork the repository
2. Create feature branch: `git checkout -b feature/NewFeature`
3. Commit changes: `git commit -m 'Add NewFeature'`
4. Push to branch: `git push origin feature/NewFeature`
5. Open Pull Request

---

## 📄 License

MIT License - Copyright (c) 2025 Michael Semera

**This tool is for educational and authorized testing purposes only.**

---

## 👤 Author

**Michael Semera**

- 💼 LinkedIn: [Michael Semera](https://www.linkedin.com/in/michael-semera-586737295/)
- 🐙 GitHub: [@MichaelKS123](https://github.com/MichaelKS123)
- 📧 Email: michaelsemera15@gmail.com

---

## 🙏 Acknowledgments

- **AFL** - Inspiration for mutation strategies
- **Google's OSS-Fuzz** - Fuzzing best practices
- **GDB Project** - Debugging infrastructure
- **Security Research Community** - Methodologies and techniques

---

## ⚖️ Ethical Use Statement

ChainOfLogs is a security research tool. Users must:
- ✅ Have explicit permission for all tested software
- ✅ Use only on authorized systems
- ✅ Follow responsible disclosure practices
- ✅ Comply with all applicable laws
- ❌ Never use for malicious purposes

**Security researchers: Report vulnerabilities responsibly!**

---

**Made with 🔗 by Michael Semera**

*Breaking software to make it stronger!*

---

**Version**: 1.0.0  
**Last Updated**: November 1, 2025  
**Status**: Production Ready ✅  
**Language**: Python 3.6+  
**License**: MIT