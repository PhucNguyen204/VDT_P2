package sigma

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// AhoCorasickPrefilter fast literal pattern matching using Aho-Corasick algorithm
type AhoCorasickPrefilter struct {
	trie        *TrieNode
	patterns    []string
	failureFunc map[*TrieNode]*TrieNode
	minLength   int
	mu          sync.RWMutex
	built       bool
}

// TrieNode node trong Aho-Corasick trie
type TrieNode struct {
	children map[rune]*TrieNode
	patterns []string // Patterns ending at this node
	failure  *TrieNode
	isEnd    bool
}

// NewAhoCorasickPrefilter tạo prefilter mới
func NewAhoCorasickPrefilter(minLength int) *AhoCorasickPrefilter {
	return &AhoCorasickPrefilter{
		trie:        newTrieNode(),
		patterns:    make([]string, 0),
		failureFunc: make(map[*TrieNode]*TrieNode),
		minLength:   minLength,
	}
}

// newTrieNode tạo trie node mới
func newTrieNode() *TrieNode {
	return &TrieNode{
		children: make(map[rune]*TrieNode),
		patterns: make([]string, 0),
	}
}

// BuildFromRules build prefilter từ compiled rules
func (p *AhoCorasickPrefilter) BuildFromRules(rules []*CompiledRule) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Collect all literals from rules
	allLiterals := make(map[string]bool)

	for _, rule := range rules {
		for _, literal := range rule.Literals {
			if len(literal) >= p.minLength {
				// Convert to lowercase for case-insensitive matching
				normalized := strings.ToLower(literal)
				allLiterals[normalized] = true
			}
		}
	}

	// Convert map to slice
	p.patterns = make([]string, 0, len(allLiterals))
	for literal := range allLiterals {
		p.patterns = append(p.patterns, literal)
	}

	// Build trie
	err := p.buildTrie()
	if err != nil {
		return fmt.Errorf("failed to build trie: %w", err)
	}

	// Build failure function
	p.buildFailureFunction()

	p.built = true

	return nil
}

// buildTrie build trie structure từ patterns
func (p *AhoCorasickPrefilter) buildTrie() error {
	p.trie = newTrieNode()

	for _, pattern := range p.patterns {
		current := p.trie

		for _, char := range pattern {
			if _, exists := current.children[char]; !exists {
				current.children[char] = newTrieNode()
			}
			current = current.children[char]
		}

		current.isEnd = true
		current.patterns = append(current.patterns, pattern)
	}

	return nil
}

// buildFailureFunction build failure function cho Aho-Corasick
func (p *AhoCorasickPrefilter) buildFailureFunction() {
	// Initialize failure function
	p.failureFunc = make(map[*TrieNode]*TrieNode)
	queue := make([]*TrieNode, 0)

	// Set failure for root's children to root
	for _, child := range p.trie.children {
		p.failureFunc[child] = p.trie
		queue = append(queue, child)
	}

	// BFS to build failure function
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for char, child := range current.children {
			queue = append(queue, child)

			// Find failure node
			failure := p.failureFunc[current]
			for failure != p.trie && failure.children[char] == nil {
				failure = p.failureFunc[failure]
			}

			if failure.children[char] != nil && failure.children[char] != child {
				p.failureFunc[child] = failure.children[char]
			} else {
				p.failureFunc[child] = p.trie
			}

			// Copy patterns from failure node
			if failureNode := p.failureFunc[child]; failureNode != p.trie {
				child.patterns = append(child.patterns, failureNode.patterns...)
			}
		}
	}
}

// ShouldProcess check if event contains any prefilter patterns
func (p *AhoCorasickPrefilter) ShouldProcess(event map[string]interface{}) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.built {
		fmt.Printf("🔍 Prefilter: Not built, allowing all events\n")
		return true, nil // If not built, process everything
	}

	fmt.Printf("🔍 Prefilter: Built with %d patterns\n", len(p.patterns))
	for i, pattern := range p.patterns {
		fmt.Printf("  Pattern %d: '%s'\n", i, pattern)
	}

	// Convert event to searchable text
	text, err := p.eventToText(event)
	if err != nil {
		fmt.Printf("❌ Prefilter: Failed to convert event to text: %v\n", err)
		return true, err // On error, process the event
	}

	fmt.Printf("🔍 Prefilter: Searching in text: '%s'\n", text)

	// Perform Aho-Corasick search
	matches := p.search(text)

	fmt.Printf("🔍 Prefilter: Found %d matches\n", len(matches))
	for i, match := range matches {
		fmt.Printf("  Match %d: '%s' at %d-%d\n", i, match.Pattern, match.Start, match.End)
	}

	return len(matches) > 0, nil
}

// eventToText convert event thành searchable text
func (p *AhoCorasickPrefilter) eventToText(event map[string]interface{}) (string, error) {
	// Simple approach: JSON encode and search trong raw text
	// More sophisticated approach would extract và normalize specific fields

	jsonBytes, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event: %w", err)
	}

	// Convert to lowercase for case-insensitive matching
	return strings.ToLower(string(jsonBytes)), nil
}

// search perform Aho-Corasick search
func (p *AhoCorasickPrefilter) search(text string) []PatternMatch {
	if p.trie == nil {
		return nil
	}

	matches := make([]PatternMatch, 0)
	current := p.trie

	for i, char := range text {
		// Follow failure links until we find a match or reach root
		for current != p.trie && current.children[char] == nil {
			current = p.failureFunc[current]
		}

		// Move to next state if possible
		if current.children[char] != nil {
			current = current.children[char]
		}

		// Report matches
		if len(current.patterns) > 0 {
			for _, pattern := range current.patterns {
				matches = append(matches, PatternMatch{
					Pattern: pattern,
					Start:   i - len(pattern) + 1,
					End:     i + 1,
				})
			}
		}
	}

	return matches
}

// PatternMatch represents a matched pattern
type PatternMatch struct {
	Pattern string `json:"pattern"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
}

// GetStats trả về prefilter statistics
func (p *AhoCorasickPrefilter) GetStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]interface{}{
		"patterns_count": len(p.patterns),
		"min_length":     p.minLength,
		"built":          p.built,
		"trie_nodes":     p.countTrieNodes(),
	}
}

// countTrieNodes đếm số nodes trong trie
func (p *AhoCorasickPrefilter) countTrieNodes() int {
	if p.trie == nil {
		return 0
	}

	visited := make(map[*TrieNode]bool)
	return p.countNodesRecursive(p.trie, visited)
}

func (p *AhoCorasickPrefilter) countNodesRecursive(node *TrieNode, visited map[*TrieNode]bool) int {
	if visited[node] {
		return 0
	}

	visited[node] = true
	count := 1

	for _, child := range node.children {
		count += p.countNodesRecursive(child, visited)
	}

	return count
}

// AddPattern add pattern to prefilter (rebuild required)
func (p *AhoCorasickPrefilter) AddPattern(pattern string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(pattern) < p.minLength {
		return nil // Skip short patterns
	}

	normalized := strings.ToLower(pattern)

	// Check if pattern already exists
	for _, existing := range p.patterns {
		if existing == normalized {
			return nil // Already exists
		}
	}

	p.patterns = append(p.patterns, normalized)
	p.built = false // Mark as needing rebuild

	return nil
}

// Rebuild rebuild prefilter after adding patterns
func (p *AhoCorasickPrefilter) Rebuild() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.built {
		return nil // Already built
	}

	err := p.buildTrie()
	if err != nil {
		return err
	}

	p.buildFailureFunction()
	p.built = true

	return nil
}

// Clear clear all patterns và reset prefilter
func (p *AhoCorasickPrefilter) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.patterns = make([]string, 0)
	p.trie = newTrieNode()
	p.failureFunc = make(map[*TrieNode]*TrieNode)
	p.built = false
}
