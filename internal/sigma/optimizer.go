package sigma

import (
	"fmt"
	"sort"
	"time"
)

// DAGOptimizer tối ưu hóa DAG structure dựa trên cawalch/sigma-engine optimizer.rs
type DAGOptimizer struct {
	config *OptimizerConfig
}

// OptimizerConfig cấu hình cho optimizer
type OptimizerConfig struct {
	EnableNodeMerging     bool          `json:"enable_node_merging"`
	EnableDeadCodeElim    bool          `json:"enable_dead_code_elimination"`
	EnableConstantFolding bool          `json:"enable_constant_folding"`
	EnableRuleReordering  bool          `json:"enable_rule_reordering"`
	MinSharedUse          int           `json:"min_shared_use"`
	OptimizationLevel     int           `json:"optimization_level"` // 0=none, 1=basic, 2=aggressive
	MaxOptimizationTime   time.Duration `json:"max_optimization_time"`
}

// DefaultOptimizerConfig trả về cấu hình mặc định
func DefaultOptimizerConfig() *OptimizerConfig {
	return &OptimizerConfig{
		EnableNodeMerging:     true,
		EnableDeadCodeElim:    true,
		EnableConstantFolding: true,
		EnableRuleReordering:  true,
		MinSharedUse:          2,
		OptimizationLevel:     2,
		MaxOptimizationTime:   10 * time.Second,
	}
}

// NewDAGOptimizer tạo optimizer mới
func NewDAGOptimizer(config *OptimizerConfig) *DAGOptimizer {
	if config == nil {
		config = DefaultOptimizerConfig()
	}
	return &DAGOptimizer{config: config}
}

// OptimizationResult kết quả optimization
type OptimizationResult struct {
	OriginalNodes    int           `json:"original_nodes"`
	OptimizedNodes   int           `json:"optimized_nodes"`
	NodesReduced     int           `json:"nodes_reduced"`
	SharedNodes      int           `json:"shared_nodes"`
	OptimizationTime time.Duration `json:"optimization_time"`
	Optimizations    []string      `json:"optimizations"`
}

// OptimizeDAG tối ưu hóa DAG structure (inspired by cawalch/sigma-engine)
func (opt *DAGOptimizer) OptimizeDAG(dag *DAGEngine, rules []*CompiledRule) (*OptimizationResult, error) {
	start := time.Now()

	result := &OptimizationResult{
		OriginalNodes: len(dag.nodes),
		Optimizations: make([]string, 0),
	}

	if opt.config.OptimizationLevel == 0 {
		result.OptimizedNodes = result.OriginalNodes
		result.OptimizationTime = time.Since(start)
		return result, nil
	}

	// Phase 1: Dead Code Elimination
	if opt.config.EnableDeadCodeElim {
		eliminated := opt.eliminateDeadCode(dag, rules)
		if eliminated > 0 {
			result.Optimizations = append(result.Optimizations,
				fmt.Sprintf("Dead code elimination: %d nodes removed", eliminated))
		}
	}

	// Phase 2: Node Merging và Shared Node Optimization
	if opt.config.EnableNodeMerging {
		merged := opt.mergeEquivalentNodes(dag)
		if merged > 0 {
			result.Optimizations = append(result.Optimizations,
				fmt.Sprintf("Node merging: %d nodes merged", merged))
		}
	}

	// Phase 3: Constant Folding
	if opt.config.EnableConstantFolding {
		folded := opt.foldConstants(dag)
		if folded > 0 {
			result.Optimizations = append(result.Optimizations,
				fmt.Sprintf("Constant folding: %d nodes simplified", folded))
		}
	}

	// Phase 4: Rule Reordering for Performance
	if opt.config.EnableRuleReordering {
		reordered := opt.reorderRulesForPerformance(dag, rules)
		if reordered {
			result.Optimizations = append(result.Optimizations, "Rules reordered for performance")
		}
	}

	// Phase 5: Shared Node Creation
	sharedCount := opt.createSharedNodes(dag)
	result.SharedNodes = sharedCount
	if sharedCount > 0 {
		result.Optimizations = append(result.Optimizations,
			fmt.Sprintf("Shared nodes: %d primitives shared", sharedCount))
	}

	result.OptimizedNodes = len(dag.nodes)
	result.NodesReduced = result.OriginalNodes - result.OptimizedNodes
	result.OptimizationTime = time.Since(start)

	return result, nil
}

// eliminateDeadCode xóa các nodes không được sử dụng
func (opt *DAGOptimizer) eliminateDeadCode(dag *DAGEngine, rules []*CompiledRule) int {
	usedNodes := make(map[string]bool)

	// Mark all nodes referenced by rules
	for _, rule := range rules {
		opt.markUsedNodes(rule.RootNode, usedNodes, dag.nodes)
	}

	// Remove unused nodes
	eliminated := 0
	for nodeID := range dag.nodes {
		if !usedNodes[nodeID] {
			delete(dag.nodes, nodeID)
			eliminated++
		}
	}

	return eliminated
}

// markUsedNodes đánh dấu nodes được sử dụng
func (opt *DAGOptimizer) markUsedNodes(node *DAGNode, used map[string]bool, allNodes map[string]*DAGNode) {
	if node == nil || used[node.ID] {
		return
	}

	used[node.ID] = true

	// Đánh dấu children
	for _, child := range node.Children {
		opt.markUsedNodes(child, used, allNodes)
	}
}

// mergeEquivalentNodes merge các nodes tương đương
func (opt *DAGOptimizer) mergeEquivalentNodes(dag *DAGEngine) int {
	nodeGroups := make(map[string][]*DAGNode)

	// Group nodes by signature
	for _, node := range dag.nodes {
		signature := opt.getNodeSignature(node)
		nodeGroups[signature] = append(nodeGroups[signature], node)
	}

	merged := 0
	for _, nodes := range nodeGroups {
		if len(nodes) > 1 {
			// Keep first node, merge others into it
			primaryNode := nodes[0]
			for i := 1; i < len(nodes); i++ {
				opt.mergeNode(primaryNode, nodes[i], dag)
				delete(dag.nodes, nodes[i].ID)
				merged++
			}
		}
	}

	return merged
}

// getNodeSignature tạo signature cho node
func (opt *DAGOptimizer) getNodeSignature(node *DAGNode) string {
	if node.Primitive != nil {
		return fmt.Sprintf("primitive:%s:%s:%v",
			node.Primitive.Type, node.Primitive.Field, node.Primitive.Value)
	}
	return fmt.Sprintf("node:%s:%d", node.Type, len(node.Children))
}

// mergeNode merge node thứ hai vào node đầu tiên
func (opt *DAGOptimizer) mergeNode(primary, secondary *DAGNode, dag *DAGEngine) {
	// Update all references to secondary node to point to primary
	for _, node := range dag.nodes {
		for i, child := range node.Children {
			if child.ID == secondary.ID {
				node.Children[i] = primary
			}
		}
	}

	// Merge any additional properties
	if secondary.Primitive != nil && primary.Primitive != nil {
		// Merge literals for prefiltering
		primary.Primitive.Literals = append(primary.Primitive.Literals,
			secondary.Primitive.Literals...)
	}
}

// foldConstants thực hiện constant folding
func (opt *DAGOptimizer) foldConstants(dag *DAGEngine) int {
	folded := 0

	for _, node := range dag.nodes {
		if opt.canFoldConstant(node) {
			opt.foldConstantNode(node)
			folded++
		}
	}

	return folded
}

// canFoldConstant kiểm tra có thể fold constant không
func (opt *DAGOptimizer) canFoldConstant(node *DAGNode) bool {
	if node.Type != "and" && node.Type != "or" {
		return false
	}

	// Check if all children are constant values
	for _, child := range node.Children {
		if child.Primitive == nil || !opt.isConstantPrimitive(child.Primitive) {
			return false
		}
	}

	return len(node.Children) > 1
}

// isConstantPrimitive kiểm tra primitive có phải constant không
func (opt *DAGOptimizer) isConstantPrimitive(prim *Primitive) bool {
	// Constants are primitives với literal values không depend vào event data
	return prim.Type == PrimitiveEquals && prim.Value != nil
}

// foldConstantNode fold constant node
func (opt *DAGOptimizer) foldConstantNode(node *DAGNode) {
	// For AND nodes: if any child is false, whole node is false
	// For OR nodes: if any child is true, whole node is true

	hasTrue := false
	hasFalse := false

	for _, child := range node.Children {
		if child.Primitive != nil {
			// Simplified logic: assume constant evaluation
			if child.Primitive.Value == true || child.Primitive.Value == "true" {
				hasTrue = true
			} else {
				hasFalse = true
			}
		}
	}

	// Create optimized node
	if node.Type == "and" && hasFalse {
		// AND với false child -> always false
		node.Children = []*DAGNode{} // Empty = false
	} else if node.Type == "or" && hasTrue {
		// OR với true child -> always true
		node.Children = []*DAGNode{} // Will need special handling
	}
}

// reorderRulesForPerformance sắp xếp lại rules cho performance
func (opt *DAGOptimizer) reorderRulesForPerformance(dag *DAGEngine, rules []*CompiledRule) bool {
	if len(rules) <= 1 {
		return false
	}

	// Sort rules by estimated execution cost (ascending)
	sort.Slice(rules, func(i, j int) bool {
		costI := opt.estimateRuleCost(rules[i])
		costJ := opt.estimateRuleCost(rules[j])
		return costI < costJ
	})

	// Update DAG rules order
	dag.rules = rules

	return true
}

// estimateRuleCost ước tính cost của rule
func (opt *DAGOptimizer) estimateRuleCost(rule *CompiledRule) int {
	cost := 0
	opt.calculateNodeCost(rule.RootNode, &cost)
	return cost
}

// calculateNodeCost tính cost của node
func (opt *DAGOptimizer) calculateNodeCost(node *DAGNode, cost *int) {
	if node == nil {
		return
	}

	// Base cost per node
	*cost += 1

	// Additional cost for complex primitives
	if node.Primitive != nil {
		switch node.Primitive.Type {
		case PrimitiveRegex:
			*cost += 10 // Regex is expensive
		case PrimitiveContains, PrimitiveEndsWith, PrimitiveStartsWith:
			*cost += 3 // String operations
		case PrimitiveEquals:
			*cost += 1 // Simple comparison
		default:
			*cost += 2
		}
	}

	// Cost for children
	for _, child := range node.Children {
		opt.calculateNodeCost(child, cost)
	}
}

// createSharedNodes tạo shared nodes cho optimization
func (opt *DAGOptimizer) createSharedNodes(dag *DAGEngine) int {
	if dag.sharedNodes == nil {
		dag.sharedNodes = make(map[string]*SharedNode)
	}

	// Find primitives used by multiple rules
	primitiveUsage := make(map[string][]string) // signature -> rule IDs

	for _, rule := range dag.rules {
		opt.collectPrimitiveUsage(rule.RootNode, rule.ID, primitiveUsage)
	}

	sharedCount := 0
	for signature, ruleIDs := range primitiveUsage {
		if len(ruleIDs) >= opt.config.MinSharedUse {
			// Create shared node
			sharedID := fmt.Sprintf("shared_%d", sharedCount)

			// Find the actual node for this signature
			for _, node := range dag.nodes {
				if opt.getNodeSignature(node) == signature {
					dag.sharedNodes[sharedID] = &SharedNode{
						Node:     node,
						RuleIDs:  ruleIDs,
						UseCount: len(ruleIDs),
						LastUsed: time.Now(),
					}
					sharedCount++
					break
				}
			}
		}
	}

	return sharedCount
}

// collectPrimitiveUsage thu thập usage của primitives
func (opt *DAGOptimizer) collectPrimitiveUsage(node *DAGNode, ruleID string, usage map[string][]string) {
	if node == nil {
		return
	}

	signature := opt.getNodeSignature(node)
	usage[signature] = append(usage[signature], ruleID)

	for _, child := range node.Children {
		opt.collectPrimitiveUsage(child, ruleID, usage)
	}
}
