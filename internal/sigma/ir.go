package sigma

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"
)

// IR - Intermediate Representation system for SIGMA rules based on cawalch/sigma-engine
type IR struct {
	Rules      []*IRRule               `json:"rules"`
	Primitives map[string]*IRPrimitive `json:"primitives"`
	Metadata   *IRMetadata             `json:"metadata"`
}

// IRRule - Intermediate representation of a compiled SIGMA rule
type IRRule struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Level       string          `json:"level"`
	Tags        []string        `json:"tags"`
	Root        *IRNode         `json:"root"`
	Primitives  []*IRPrimitive  `json:"primitives"`
	Metadata    *IRRuleMetadata `json:"metadata"`
	Hash        uint64          `json:"hash"`
}

// IRNode - Node in the IR tree structure
type IRNode struct {
	ID          string          `json:"id"`
	Type        IRNodeType      `json:"type"`
	Operation   IROperation     `json:"operation,omitempty"`
	Primitive   *IRPrimitive    `json:"primitive,omitempty"`
	Children    []*IRNode       `json:"children,omitempty"`
	Parent      *IRNode         `json:"parent,omitempty"`
	Metadata    *IRNodeMetadata `json:"metadata"`
	Hash        uint64          `json:"hash"`
	SharedCount int             `json:"shared_count"`
	Optimized   bool            `json:"optimized"`
}

// IRPrimitive - Primitive matching operation in IR
type IRPrimitive struct {
	ID            string          `json:"id"`
	Type          IRPrimitiveType `json:"type"`
	Field         string          `json:"field"`
	Value         interface{}     `json:"value"`
	Modifier      string          `json:"modifier,omitempty"`
	Negated       bool            `json:"negated"`
	CaseSensitive bool            `json:"case_sensitive"`
	Literals      []string        `json:"literals,omitempty"`
	Pattern       string          `json:"pattern,omitempty"`
	Hash          uint64          `json:"hash"`
	UseCount      int             `json:"use_count"`
	Complexity    int             `json:"complexity"`
}

// IRMetadata - Global IR metadata
type IRMetadata struct {
	Version           string        `json:"version"`
	CreatedAt         time.Time     `json:"created_at"`
	RuleCount         int           `json:"rule_count"`
	PrimitiveCount    int           `json:"primitive_count"`
	SharedNodes       int           `json:"shared_nodes"`
	OptimizationLevel int           `json:"optimization_level"`
	Statistics        *IRStatistics `json:"statistics"`
}

// IRRuleMetadata - Rule-specific metadata
type IRRuleMetadata struct {
	SourceFile     string    `json:"source_file,omitempty"`
	LineNumber     int       `json:"line_number,omitempty"`
	ParsedAt       time.Time `json:"parsed_at"`
	Complexity     int       `json:"complexity"`
	NodeCount      int       `json:"node_count"`
	PrimitiveCount int       `json:"primitive_count"`
	EstimatedCost  float64   `json:"estimated_cost"`
	Dependencies   []string  `json:"dependencies,omitempty"`
}

// IRNodeMetadata - Node-specific metadata
type IRNodeMetadata struct {
	EstimatedCost    float64       `json:"estimated_cost"`
	EstimatedHitRate float64       `json:"estimated_hit_rate"`
	Selectivity      float64       `json:"selectivity"`
	ExecutionCount   int64         `json:"execution_count"`
	AverageTime      time.Duration `json:"average_time"`
	CacheHitRate     float64       `json:"cache_hit_rate"`
	SharedWith       []string      `json:"shared_with,omitempty"`
}

// IRStatistics - Global statistics for optimization
type IRStatistics struct {
	TotalNodes          int     `json:"total_nodes"`
	SharedNodes         int     `json:"shared_nodes"`
	UniquePatterns      int     `json:"unique_patterns"`
	CompressionRatio    float64 `json:"compression_ratio"`
	EstimatedMemory     int64   `json:"estimated_memory"`
	OptimizationSavings float64 `json:"optimization_savings"`
}

// IRNodeType - Types of IR nodes
type IRNodeType string

const (
	IRNodeAnd       IRNodeType = "and"
	IRNodeOr        IRNodeType = "or"
	IRNodeNot       IRNodeType = "not"
	IRNodePrimitive IRNodeType = "primitive"
	IRNodeRoot      IRNodeType = "root"
	IRNodeOptimized IRNodeType = "optimized"
)

// IROperation - Logical operations in IR
type IROperation string

const (
	IROpAnd   IROperation = "and"
	IROpOr    IROperation = "or"
	IROpNot   IROperation = "not"
	IROpGroup IROperation = "group"
)

// IRPrimitiveType - Types of primitive operations
type IRPrimitiveType string

const (
	IRPrimEquals      IRPrimitiveType = "equals"
	IRPrimContains    IRPrimitiveType = "contains"
	IRPrimStartsWith  IRPrimitiveType = "startswith"
	IRPrimEndsWith    IRPrimitiveType = "endswith"
	IRPrimRegex       IRPrimitiveType = "regex"
	IRPrimExists      IRPrimitiveType = "exists"
	IRPrimLessThan    IRPrimitiveType = "lt"
	IRPrimGreaterThan IRPrimitiveType = "gt"
	IRPrimIn          IRPrimitiveType = "in"
	IRPrimCIDR        IRPrimitiveType = "cidr"
)

// NewIR - Create new IR instance
func NewIR() *IR {
	return &IR{
		Rules:      make([]*IRRule, 0),
		Primitives: make(map[string]*IRPrimitive),
		Metadata: &IRMetadata{
			Version:           "1.0.0",
			CreatedAt:         time.Now(),
			OptimizationLevel: 0,
			Statistics:        &IRStatistics{},
		},
	}
}

// AddRule - Add rule to IR
func (ir *IR) AddRule(rule *IRRule) {
	rule.Hash = ir.calculateRuleHash(rule)
	ir.Rules = append(ir.Rules, rule)

	// Update primitives map
	for _, primitive := range rule.Primitives {
		existing, exists := ir.Primitives[primitive.ID]
		if exists {
			existing.UseCount++
		} else {
			ir.Primitives[primitive.ID] = primitive
			primitive.UseCount = 1
		}
	}

	ir.updateMetadata()
}

// OptimizeSharedNodes - Optimize shared nodes across rules
func (ir *IR) OptimizeSharedNodes() *IROptimizationResult {
	result := &IROptimizationResult{
		StartTime:      time.Now(),
		NodesProcessed: 0,
		NodesShared:    0,
		MemorySaved:    0,
	}

	// Find shareable nodes
	nodeGroups := ir.groupNodesBySignature()

	for _, nodes := range nodeGroups {
		if len(nodes) > 1 {
			// Create shared node
			sharedNode := ir.createSharedNode(nodes)
			ir.replaceNodesWithShared(nodes, sharedNode)

			result.NodesShared += len(nodes) - 1
			result.MemorySaved += ir.estimateMemorySaving(nodes)
		}
		result.NodesProcessed += len(nodes)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	ir.Metadata.SharedNodes = result.NodesShared
	ir.updateStatistics()

	return result
}

// OptimizePrimitives - Optimize primitive operations
func (ir *IR) OptimizePrimitives() *IROptimizationResult {
	result := &IROptimizationResult{
		StartTime:           time.Now(),
		PrimitivesProcessed: len(ir.Primitives),
	}

	// Find duplicate primitives
	primitiveGroups := ir.groupPrimitivesBySignature()

	for _, primitives := range primitiveGroups {
		if len(primitives) > 1 {
			// Merge primitives
			merged := ir.mergePrimitives(primitives)
			ir.replacePrimitivesWithMerged(primitives, merged)

			result.PrimitivesOptimized += len(primitives) - 1
		}
	}

	// Sort primitives by selectivity (most selective first)
	ir.sortPrimitivesBySelectivity()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result
}

// ExtractLiterals - Extract literal patterns for prefiltering
func (ir *IR) ExtractLiterals() []string {
	literals := make(map[string]bool)

	for _, primitive := range ir.Primitives {
		if primitive.Literals != nil {
			for _, literal := range primitive.Literals {
				if len(literal) >= 3 { // Minimum length for effective prefiltering
					literals[literal] = true
				}
			}
		}

		// Extract from patterns
		if primitive.Pattern != "" {
			extracted := ir.extractLiteralsFromPattern(primitive.Pattern, primitive.Type)
			for _, literal := range extracted {
				if len(literal) >= 3 {
					literals[literal] = true
				}
			}
		}
	}

	// Convert to sorted slice
	result := make([]string, 0, len(literals))
	for literal := range literals {
		result = append(result, literal)
	}
	sort.Strings(result)

	return result
}

// AnalyzeComplexity - Analyze computational complexity
func (ir *IR) AnalyzeComplexity() *IRComplexityAnalysis {
	analysis := &IRComplexityAnalysis{
		Rules:     make([]*IRRuleComplexity, len(ir.Rules)),
		TotalCost: 0,
		MaxCost:   0,
		AvgCost:   0,
	}

	for i, rule := range ir.Rules {
		ruleComplexity := ir.analyzeRuleComplexity(rule)
		analysis.Rules[i] = ruleComplexity
		analysis.TotalCost += ruleComplexity.EstimatedCost

		if ruleComplexity.EstimatedCost > analysis.MaxCost {
			analysis.MaxCost = ruleComplexity.EstimatedCost
			analysis.MostExpensive = rule.ID
		}
	}

	if len(ir.Rules) > 0 {
		analysis.AvgCost = analysis.TotalCost / float64(len(ir.Rules))
	}

	return analysis
}

// IROptimizationResult - Result of optimization operation
type IROptimizationResult struct {
	StartTime           time.Time     `json:"start_time"`
	EndTime             time.Time     `json:"end_time"`
	Duration            time.Duration `json:"duration"`
	NodesProcessed      int           `json:"nodes_processed"`
	NodesShared         int           `json:"nodes_shared"`
	PrimitivesProcessed int           `json:"primitives_processed"`
	PrimitivesOptimized int           `json:"primitives_optimized"`
	MemorySaved         int64         `json:"memory_saved"`
	ComputationSaved    float64       `json:"computation_saved"`
}

// IRComplexityAnalysis - Complexity analysis results
type IRComplexityAnalysis struct {
	Rules         []*IRRuleComplexity `json:"rules"`
	TotalCost     float64             `json:"total_cost"`
	MaxCost       float64             `json:"max_cost"`
	AvgCost       float64             `json:"avg_cost"`
	MostExpensive string              `json:"most_expensive"`
}

// IRRuleComplexity - Rule complexity metrics
type IRRuleComplexity struct {
	RuleID         string  `json:"rule_id"`
	NodeCount      int     `json:"node_count"`
	PrimitiveCount int     `json:"primitive_count"`
	MaxDepth       int     `json:"max_depth"`
	EstimatedCost  float64 `json:"estimated_cost"`
	Selectivity    float64 `json:"selectivity"`
}

// Helper methods

func (ir *IR) calculateRuleHash(rule *IRRule) uint64 {
	h := fnv.New64a()
	h.Write([]byte(rule.ID))
	h.Write([]byte(rule.Title))
	// Add more fields as needed
	return h.Sum64()
}

func (ir *IR) updateMetadata() {
	ir.Metadata.RuleCount = len(ir.Rules)
	ir.Metadata.PrimitiveCount = len(ir.Primitives)
}

func (ir *IR) groupNodesBySignature() map[string][]*IRNode {
	groups := make(map[string][]*IRNode)

	for _, rule := range ir.Rules {
		ir.collectNodesForGrouping(rule.Root, groups)
	}

	return groups
}

func (ir *IR) collectNodesForGrouping(node *IRNode, groups map[string][]*IRNode) {
	if node == nil {
		return
	}

	signature := ir.calculateNodeSignature(node)
	groups[signature] = append(groups[signature], node)

	for _, child := range node.Children {
		ir.collectNodesForGrouping(child, groups)
	}
}

func (ir *IR) calculateNodeSignature(node *IRNode) string {
	var parts []string
	parts = append(parts, string(node.Type))

	if node.Primitive != nil {
		parts = append(parts, string(node.Primitive.Type))
		parts = append(parts, node.Primitive.Field)
		parts = append(parts, fmt.Sprintf("%v", node.Primitive.Value))
	}

	return strings.Join(parts, "|")
}

func (ir *IR) createSharedNode(nodes []*IRNode) *IRNode {
	if len(nodes) == 0 {
		return nil
	}

	// Use first node as template
	template := nodes[0]
	shared := &IRNode{
		ID:          fmt.Sprintf("shared_%d", time.Now().UnixNano()),
		Type:        template.Type,
		Operation:   template.Operation,
		Primitive:   template.Primitive,
		SharedCount: len(nodes),
		Optimized:   true,
		Metadata:    &IRNodeMetadata{},
	}

	// Copy children if any
	if len(template.Children) > 0 {
		shared.Children = make([]*IRNode, len(template.Children))
		copy(shared.Children, template.Children)
	}

	return shared
}

func (ir *IR) replaceNodesWithShared(nodes []*IRNode, shared *IRNode) {
	for _, node := range nodes {
		if node.Parent != nil {
			// Replace in parent's children
			for i, child := range node.Parent.Children {
				if child == node {
					node.Parent.Children[i] = shared
					break
				}
			}
		}
	}
}

func (ir *IR) groupPrimitivesBySignature() map[string][]*IRPrimitive {
	groups := make(map[string][]*IRPrimitive)

	for _, primitive := range ir.Primitives {
		signature := ir.calculatePrimitiveSignature(primitive)
		groups[signature] = append(groups[signature], primitive)
	}

	return groups
}

func (ir *IR) calculatePrimitiveSignature(primitive *IRPrimitive) string {
	return fmt.Sprintf("%s|%s|%v|%s|%t",
		primitive.Type, primitive.Field, primitive.Value,
		primitive.Modifier, primitive.Negated)
}

func (ir *IR) mergePrimitives(primitives []*IRPrimitive) *IRPrimitive {
	if len(primitives) == 0 {
		return nil
	}

	merged := *primitives[0] // Copy first primitive
	merged.ID = fmt.Sprintf("merged_%d", time.Now().UnixNano())
	merged.UseCount = 0

	for _, primitive := range primitives {
		merged.UseCount += primitive.UseCount
	}

	return &merged
}

func (ir *IR) replacePrimitivesWithMerged(primitives []*IRPrimitive, merged *IRPrimitive) {
	// Remove old primitives and add merged
	for _, primitive := range primitives {
		delete(ir.Primitives, primitive.ID)
	}
	ir.Primitives[merged.ID] = merged
}

func (ir *IR) sortPrimitivesBySelectivity() {
	// This would involve actual selectivity calculation
	// For now, sort by estimated complexity (simpler operations first)
	primitives := make([]*IRPrimitive, 0, len(ir.Primitives))
	for _, primitive := range ir.Primitives {
		primitives = append(primitives, primitive)
	}

	sort.Slice(primitives, func(i, j int) bool {
		return primitives[i].Complexity < primitives[j].Complexity
	})
}

func (ir *IR) extractLiteralsFromPattern(pattern string, primitiveType IRPrimitiveType) []string {
	var literals []string

	switch primitiveType {
	case IRPrimContains:
		// For contains, the entire pattern is a literal
		literals = append(literals, pattern)
	case IRPrimStartsWith:
		// For startswith, use the prefix
		literals = append(literals, pattern)
	case IRPrimEndsWith:
		// For endswith, use the suffix
		literals = append(literals, pattern)
	case IRPrimEquals:
		// For exact match, the entire pattern is literal
		literals = append(literals, pattern)
	}

	return literals
}

func (ir *IR) analyzeRuleComplexity(rule *IRRule) *IRRuleComplexity {
	complexity := &IRRuleComplexity{
		RuleID:         rule.ID,
		NodeCount:      ir.countNodes(rule.Root),
		PrimitiveCount: len(rule.Primitives),
		MaxDepth:       ir.calculateMaxDepth(rule.Root),
	}

	// Estimate cost based on node count and types
	complexity.EstimatedCost = float64(complexity.NodeCount) * 1.0
	for _, primitive := range rule.Primitives {
		complexity.EstimatedCost += float64(primitive.Complexity) * 0.5
	}

	// Calculate selectivity (simplified)
	complexity.Selectivity = 1.0 / float64(complexity.PrimitiveCount+1)

	return complexity
}

func (ir *IR) countNodes(node *IRNode) int {
	if node == nil {
		return 0
	}

	count := 1
	for _, child := range node.Children {
		count += ir.countNodes(child)
	}

	return count
}

func (ir *IR) calculateMaxDepth(node *IRNode) int {
	if node == nil {
		return 0
	}

	maxChildDepth := 0
	for _, child := range node.Children {
		depth := ir.calculateMaxDepth(child)
		if depth > maxChildDepth {
			maxChildDepth = depth
		}
	}

	return maxChildDepth + 1
}

func (ir *IR) estimateMemorySaving(nodes []*IRNode) int64 {
	// Simplified memory estimation
	return int64(len(nodes)-1) * 64 // Assume 64 bytes per node saved
}

func (ir *IR) updateStatistics() {
	stats := ir.Metadata.Statistics
	stats.TotalNodes = 0
	stats.SharedNodes = ir.Metadata.SharedNodes

	for _, rule := range ir.Rules {
		stats.TotalNodes += ir.countNodes(rule.Root)
	}

	stats.UniquePatterns = len(ir.Primitives)
	if stats.TotalNodes > 0 {
		stats.CompressionRatio = float64(stats.SharedNodes) / float64(stats.TotalNodes)
	}
}
