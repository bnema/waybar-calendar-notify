package calendar

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

// Runtime security measures for additional protection

// Anti-debugging environment variable checks
//garble:controlflow flatten_passes=2 junk_jumps=max
func antiDebugEnvCheck() bool {
	// Check for common debugger environment variables
	debugVars := []string{
		"GDBSERVER", "IDA_PATH", "RADARE2_PREFIX", "GHIDRA_PATH",
		"_", // Common in debugging sessions
		"TERM_PROGRAM", // Some IDEs set this
		"VSCODE_INJECTION", // VSCode debugging
		"INTELLIJ_ENVIRONMENT_READER", // IntelliJ
	}
	
	suspiciousCount := 0
	for _, v := range debugVars {
		if val := os.Getenv(v); val != "" {
			// Some of these are legitimate, so count instead of immediate fail
			if strings.Contains(strings.ToLower(val), "debug") ||
				strings.Contains(strings.ToLower(val), "ida") ||
				strings.Contains(strings.ToLower(val), "ghidra") {
				suspiciousCount++
			}
		}
	}
	
	// If multiple suspicious variables, likely in a debugging environment
	return suspiciousCount >= 2
}

// Process name checks for common reverse engineering tools
//garble:controlflow flatten_passes=1 junk_jumps=5
func antiDebugProcessCheck() bool {
	// This is a simple check - in a real scenario, we'd check running processes
	// For now, just check some environment indicators
	
	// Check if we're running under strace/ltrace
	if os.Getenv("LD_PRELOAD") != "" {
		return true
	}
	
	// Check for common debugging tools in PATH
	suspiciousTools := []string{"gdb", "lldb", "radare2", "ida", "ghidra"}
	for _, tool := range suspiciousTools {
		// Simple check - in production you might want more sophisticated detection
		if _, err := os.Stat("/usr/bin/" + tool); err == nil {
			// Tool exists, but that doesn't mean we're being debugged
			continue
		}
	}
	
	return false
}

// Timing-based anti-debugging check
//garble:controlflow flatten_passes=2 block_splits=max
func antiDebugTimingCheck() bool {
	iterations := 10000
	start := time.Now()
	
	// Perform some computation
	sum := 0
	for i := 0; i < iterations; i++ {
		sum += i * i
	}
	
	elapsed := time.Since(start)
	
	// If it takes too long, might be running under a debugger
	// This threshold is very rough and environment-dependent
	if elapsed > time.Millisecond*100 {
		return true
	}
	
	// Use the sum to prevent optimization
	_ = sum
	
	return false
}

// Memory pattern checks
//garble:controlflow flatten_passes=1
func antiDebugMemoryCheck() bool {
	// Check for suspicious memory patterns that might indicate debugging
	
	// Simple heap check - debuggers might allocate specific patterns
	testBytes := make([]byte, 1024)
	for i := range testBytes {
		testBytes[i] = byte(i % 256)
	}
	
	// Check if memory contains unexpected patterns
	zeroCount := 0
	for _, b := range testBytes {
		if b == 0 {
			zeroCount++
		}
	}
	
	// Clear test memory
	clearBytesSecure(testBytes)
	
	// If too many zeros, might indicate memory tampering
	return zeroCount > len(testBytes)/10
}

// Comprehensive anti-debugging check
//garble:controlflow flatten_passes=3 junk_jumps=max trash_blocks=1
func comprehensiveAntiDebugCheck() bool {
	// Run multiple checks
	checks := []func() bool{
		antiDebugEnvCheck,
		antiDebugProcessCheck,
		antiDebugTimingCheck,
		antiDebugMemoryCheck,
	}
	
	suspiciousCount := 0
	for _, check := range checks {
		if check() {
			suspiciousCount++
		}
		
		// Add some delay between checks
		time.Sleep(time.Microsecond * 10)
	}
	
	// If multiple checks fail, likely being debugged/analyzed
	return suspiciousCount >= 2
}

// Secure memory clearing with multiple passes
//garble:controlflow flatten_passes=1
func clearBytesSecure(b []byte) {
	if len(b) == 0 {
		return
	}
	
	// Multiple passes with different patterns
	patterns := []byte{0x00, 0xFF, 0xAA, 0x55, 0x00}
	
	for _, pattern := range patterns {
		for i := range b {
			b[i] = pattern
		}
		runtime.KeepAlive(b) // Prevent optimization
	}
	
	// Final zero pass
	for i := range b {
		b[i] = 0
	}
}

// Secure string clearing with multiple overwrites
//garble:controlflow flatten_passes=1
func clearStringSecure(s *string) {
	if s == nil || *s == "" {
		return
	}
	
	// Get the underlying byte array
	b := unsafe.Slice(unsafe.StringData(*s), len(*s))
	
	// Multiple overwrite passes
	patterns := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00}
	
	for _, pattern := range patterns {
		for i := range b {
			b[i] = pattern
		}
		runtime.KeepAlive(b)
	}
	
	// Set to empty string
	*s = ""
	
	// Force garbage collection
	runtime.GC()
	runtime.GC() // Call twice for extra certainty
}

// Memory pressure to confuse memory dumps
//garble:controlflow flatten_passes=2 junk_jumps=3
func createMemoryNoise() {
	// Create some memory noise to make dumps less useful
	noiseData := make([][]byte, 10)
	
	for i := range noiseData {
		noiseData[i] = make([]byte, 1024)
		// Fill with pseudo-random data based on current time
		seed := time.Now().UnixNano() + int64(i)
		for j := range noiseData[i] {
			noiseData[i][j] = byte(seed % 256)
			seed = (seed * 1103515245 + 12345) % (1 << 31)
		}
	}
	
	// Keep noise alive briefly
	runtime.KeepAlive(noiseData)
	
	// Clear noise data
	for i := range noiseData {
		clearBytesSecure(noiseData[i])
	}
}

// Stack frame obfuscation
//garble:controlflow flatten_passes=1 block_splits=max
func obfuscateStackFrame() {
	// Create dummy function calls to obfuscate the call stack
	dummy1 := func() int {
		dummy2 := func() int {
			dummy3 := func() int {
				return runtime.NumCPU()
			}
			return dummy3() + 1
		}
		return dummy2() + 1
	}
	
	result := dummy1()
	_ = result // Use the result to prevent optimization
}

// Enhanced security validation for embedded secrets loading
//garble:controlflow flatten_passes=3 junk_jumps=max block_splits=max trash_blocks=1
func validateSecurityEnvironment() error {
	// Create memory noise
	createMemoryNoise()
	
	// Obfuscate call stack
	obfuscateStackFrame()
	
	// Comprehensive anti-debugging check
	if comprehensiveAntiDebugCheck() {
		// Don't immediately fail, but add delays
		for i := 0; i < 10; i++ {
			time.Sleep(time.Millisecond * 100)
			if i%3 == 0 {
				createMemoryNoise()
			}
		}
		// Now return error
		return fmt.Errorf("security validation failed: suspicious runtime environment detected")
	}
	
	// Additional timing check
	start := time.Now()
	for i := 0; i < 1000; i++ {
		_ = fmt.Sprintf("%d", i*i)
	}
	
	if time.Since(start) > time.Millisecond*50 {
		return fmt.Errorf("security validation failed: performance anomaly detected")
	}
	
	return nil
}

// Runtime integrity check for the binary
//garble:controlflow flatten_passes=2 junk_jumps=5
func performRuntimeIntegrityCheck() bool {
	// Simple integrity check - in practice this could be more sophisticated
	
	// Check that we can allocate memory normally
	testAllocation := make([]byte, 4096)
	defer clearBytesSecure(testAllocation)
	
	// Check basic runtime functions work
	if runtime.NumCPU() < 1 {
		return false
	}
	
	// Check time functions work
	now := time.Now()
	if now.Unix() < 1000000000 { // Should be well past year 2000
		return false
	}
	
	// Basic filesystem checks
	if _, err := os.Getwd(); err != nil {
		return false
	}
	
	return true
}

// Initialize security runtime - should be called early in program startup
//garble:controlflow flatten_passes=2 block_splits=max
func InitializeSecurityRuntime() error {
	// Perform runtime integrity check
	if !performRuntimeIntegrityCheck() {
		return fmt.Errorf("runtime integrity check failed")
	}
	
	// Validate security environment
	if err := validateSecurityEnvironment(); err != nil {
		return err
	}
	
	// Create initial memory noise
	createMemoryNoise()
	
	return nil
}