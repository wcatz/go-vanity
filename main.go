package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/blinklabs-io/bursa/address"
	"github.com/blinklabs-io/bursa/key"
)

func main() {
	// Parse command line flags
	targetSuffix := flag.String("suffix", "", "Target suffix for vanity stake key (e.g., 'blink')")
	maxIterations := flag.Int64("max", 0, "Maximum iterations (0 = unlimited)")
	verbose := flag.Bool("verbose", false, "Enable verbose output")

	flag.Parse()

	// Check if suffix was provided
	if *targetSuffix == "" {
		log.Fatal("Error: Target suffix is required. Use -suffix flag (e.g., -suffix blink)")
	}

	fmt.Printf("Searching for Cardano stake key ending in '%s'...\n", *targetSuffix)
	if *maxIterations > 0 {
		fmt.Printf("Max iterations: %d\n", *maxIterations)
	}
	fmt.Println()

	// Generate vanity key using Bursa
	stakeKey, iterations, err := GenerateVanityStakeKey(*targetSuffix, *maxIterations, *verbose)
	if err != nil {
		log.Fatalf("Error generating vanity stake key: %v", err)
	}

	// Display results
	fmt.Println("✓ Vanity stake key found!")
	fmt.Printf("Iterations: %d\n", iterations)
	fmt.Printf("Stake Address: %s\n", stakeKey)
	fmt.Printf("Suffix Match: ...%%s\n", strings.ToLower(*targetSuffix))
}