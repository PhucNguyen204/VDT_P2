package sigma

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Compiler chuyển đổi SIGMA YAML rules thành DAG structure
type Compiler struct {
	fieldMapper    *FieldMapper
	primitiveCache map[string]*Primitive
	ruleCache      map[string]*CompiledRule
}

// NewCompiler tạo compiler mới
func NewCompiler() *Compiler {
	return &Compiler{
		fieldMapper:    NewFieldMapperWithCase(true), // Case-sensitive for exact field matching
		primitiveCache: make(map[string]*Primitive),
		ruleCache:      make(map[string]*CompiledRule),
	}
}

// SigmaRule structure của SIGMA rule YAML
type SigmaRule struct {
	Title          string                 `yaml:"title"`
	ID             string                 `yaml:"id"`
	Description    string                 `yaml:"description"`
	Author         string                 `yaml:"author"`
	Date           string                 `yaml:"date"`
	Level          string                 `yaml:"level"`
	Tags           []string               `yaml:"tags"`
	LogSource      map[string]interface{} `yaml:"logsource"`
	Detection      map[string]interface{} `yaml:"detection"`
	References     []string               `yaml:"references"`
	FalsePositives []string               `yaml:"falsepositives"`
}

// CompiledRule rule đã được compile thành DAG
type CompiledRule struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Level       string                 `json:"level"`
	Tags        []string               `json:"tags"`
	RootNode    *DAGNode               `json:"root_node"`
	Primitives  []*Primitive           `json:"primitives"`
	LogSource   map[string]interface{} `json:"logsource"`
	Condition   string                 `json:"condition"`
	Literals    []string               `json:"literals"` // For prefiltering
}

// Use PrimitiveType from types.go - removed duplicates

// Primitive cơ bản operation
type Primitive struct {
	ID            string         `json:"id"`
	Type          PrimitiveType  `json:"type"`
	Field         string         `json:"field"`
	Value         interface{}    `json:"value"`
	Values        []interface{}  `json:"values"` // For list comparisons
	CaseSensitive bool           `json:"case_sensitive"`
	CompiledRegex *regexp.Regexp `json:"-"`
	Literals      []string       `json:"literals"` // For prefiltering
}

// DAGNodeType loại DAG node
type DAGNodeType string

const (
	NodePrimitive DAGNodeType = "primitive"
	NodeAnd       DAGNodeType = "and"
	NodeOr        DAGNodeType = "or"
	NodeNot       DAGNodeType = "not"
)

// DAGNode node trong DAG
type DAGNode struct {
	ID        string      `json:"id"`
	Type      DAGNodeType `json:"type"`
	Primitive *Primitive  `json:"primitive,omitempty"`
	Children  []*DAGNode  `json:"children,omitempty"`
	Parent    *DAGNode    `json:"-"`
}

// CompileRuleset compile nhiều rules thành DAG
func (c *Compiler) CompileRuleset(rulesYAML []string) ([]*CompiledRule, error) {
	compiledRules := make([]*CompiledRule, 0, len(rulesYAML))

	for i, ruleYAML := range rulesYAML {
		rule, err := c.CompileRule(ruleYAML)
		if err != nil {
			return nil, fmt.Errorf("failed to compile rule %d: %w", i, err)
		}
		compiledRules = append(compiledRules, rule)
	}

	return compiledRules, nil
}

// CompileRule compile một SIGMA rule YAML thành CompiledRule
func (c *Compiler) CompileRule(ruleYAML string) (*CompiledRule, error) {
	// Parse YAML
	var sigmaRule SigmaRule
	err := yaml.Unmarshal([]byte(ruleYAML), &sigmaRule)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Check cache
	if cached, exists := c.ruleCache[sigmaRule.ID]; exists {
		return cached, nil
	}

	// Compile detection logic
	rootNode, primitives, literals, err := c.compileDetection(sigmaRule.Detection)
	if err != nil {
		return nil, fmt.Errorf("failed to compile detection: %w", err)
	}

	// Create compiled rule
	compiled := &CompiledRule{
		ID:          sigmaRule.ID,
		Title:       sigmaRule.Title,
		Description: sigmaRule.Description,
		Level:       sigmaRule.Level,
		Tags:        sigmaRule.Tags,
		RootNode:    rootNode,
		Primitives:  primitives,
		LogSource:   sigmaRule.LogSource,
		Condition:   getConditionString(sigmaRule.Detection),
		Literals:    literals,
	}

	// Cache result
	c.ruleCache[sigmaRule.ID] = compiled

	return compiled, nil
}

// compileDetection compile detection section thành DAG
func (c *Compiler) compileDetection(detection map[string]interface{}) (*DAGNode, []*Primitive, []string, error) {
	// Extract condition
	conditionValue, exists := detection["condition"]
	if !exists {
		return nil, nil, nil, fmt.Errorf("missing condition in detection")
	}

	condition, ok := conditionValue.(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("condition must be string")
	}

	// Parse selections
	selections := make(map[string]*DAGNode)
	allPrimitives := make([]*Primitive, 0)
	allLiterals := make([]string, 0)

	for key, value := range detection {
		if key == "condition" {
			continue
		}

		// Compile selection
		node, primitives, literals, err := c.compileSelection(key, value)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to compile selection %s: %w", key, err)
		}

		selections[key] = node
		allPrimitives = append(allPrimitives, primitives...)
		allLiterals = append(allLiterals, literals...)
	}

	// Parse and build condition tree
	rootNode, err := c.parseCondition(condition, selections)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse condition: %w", err)
	}

	return rootNode, allPrimitives, allLiterals, nil
}

// compileSelection compile một selection thành DAG node - Enhanced to handle multiple SIGMA formats
func (c *Compiler) compileSelection(name string, selection interface{}) (*DAGNode, []*Primitive, []string, error) {
	switch sel := selection.(type) {
	case map[string]interface{}:
		// Standard map format: selection: { EventID: 4624, LogonType: 2 }
		return c.compileMapSelection(name, sel)

	case []interface{}:
		// List format: selection: [ value1, value2 ] - treat as OR condition
		return c.compileListSelection(name, sel)

	case string:
		// String format: selection: "single_value" - treat as keyword match
		return c.compileStringSelection(name, sel)

	case nil:
		// Empty selection - skip silently
		return nil, nil, nil, fmt.Errorf("empty selection %s", name)

	default:
		// Unsupported format - skip with warning instead of failing
		return nil, nil, nil, fmt.Errorf("unsupported selection format for %s: %T (skipping)", name, selection)
	}
}

// compileMapSelection handles map-based selections (most common format)
func (c *Compiler) compileMapSelection(name string, selectionMap map[string]interface{}) (*DAGNode, []*Primitive, []string, error) {
	var rootNode *DAGNode
	primitives := make([]*Primitive, 0)
	literals := make([]string, 0)

	if len(selectionMap) == 0 {
		return nil, nil, nil, fmt.Errorf("empty selection map for %s", name)
	}

	if len(selectionMap) == 1 {
		// Single field selection
		for field, value := range selectionMap {
			primitive, err := c.compilePrimitive(field, value)
			if err != nil {
				return nil, nil, nil, err
			}

			primitives = append(primitives, primitive)
			literals = append(literals, primitive.Literals...)

			rootNode = &DAGNode{
				ID:        generateNodeID(),
				Type:      NodePrimitive,
				Primitive: primitive,
			}
		}
	} else {
		// Multiple fields - AND them together
		children := make([]*DAGNode, 0, len(selectionMap))

		for field, value := range selectionMap {
			primitive, err := c.compilePrimitive(field, value)
			if err != nil {
				// Skip invalid primitives instead of failing entire rule
				continue
			}

			primitives = append(primitives, primitive)
			literals = append(literals, primitive.Literals...)

			childNode := &DAGNode{
				ID:        generateNodeID(),
				Type:      NodePrimitive,
				Primitive: primitive,
			}
			children = append(children, childNode)
		}

		if len(children) == 0 {
			return nil, nil, nil, fmt.Errorf("no valid primitives in selection %s", name)
		}

		rootNode = &DAGNode{
			ID:       generateNodeID(),
			Type:     NodeAnd,
			Children: children,
		}

		// Set parent references
		for _, child := range children {
			child.Parent = rootNode
		}
	}

	return rootNode, primitives, literals, nil
}

// compileListSelection handles list-based selections (OR conditions)
func (c *Compiler) compileListSelection(name string, selectionList []interface{}) (*DAGNode, []*Primitive, []string, error) {
	if len(selectionList) == 0 {
		return nil, nil, nil, fmt.Errorf("empty selection list for %s", name)
	}

	var rootNode *DAGNode
	primitives := make([]*Primitive, 0)
	literals := make([]string, 0)
	children := make([]*DAGNode, 0)

	// Treat list as OR condition over multiple values
	for i, item := range selectionList {
		fieldName := fmt.Sprintf("%s_item_%d", name, i)

		primitive, err := c.compilePrimitive(fieldName, item)
		if err != nil {
			continue // Skip invalid items
		}

		primitives = append(primitives, primitive)
		literals = append(literals, primitive.Literals...)

		childNode := &DAGNode{
			ID:        generateNodeID(),
			Type:      NodePrimitive,
			Primitive: primitive,
		}
		children = append(children, childNode)
	}

	if len(children) == 0 {
		return nil, nil, nil, fmt.Errorf("no valid items in selection list %s", name)
	}

	if len(children) == 1 {
		rootNode = children[0]
	} else {
		rootNode = &DAGNode{
			ID:       generateNodeID(),
			Type:     NodeOr,
			Children: children,
		}

		// Set parent references
		for _, child := range children {
			child.Parent = rootNode
		}
	}

	return rootNode, primitives, literals, nil
}

// compileStringSelection handles string-based selections (keyword matching)
func (c *Compiler) compileStringSelection(name string, selectionString string) (*DAGNode, []*Primitive, []string, error) {
	if len(strings.TrimSpace(selectionString)) == 0 {
		return nil, nil, nil, fmt.Errorf("empty selection string for %s", name)
	}

	// Treat string as a keyword/contains match
	primitive, err := c.compilePrimitive("keywords", selectionString)
	if err != nil {
		return nil, nil, nil, err
	}

	rootNode := &DAGNode{
		ID:        generateNodeID(),
		Type:      NodePrimitive,
		Primitive: primitive,
	}

	return rootNode, []*Primitive{primitive}, primitive.Literals, nil
}

// compilePrimitive compile field-value pair thành Primitive
func (c *Compiler) compilePrimitive(field string, value interface{}) (*Primitive, error) {
	// Parse modifiers from field name
	originalField := field
	fieldParts := strings.Split(field, "|")
	field = fieldParts[0]

	// Apply field mapping
	mappedField := c.fieldMapper.MapField(field)

	// Debug field mapping
	if mappedField != field {
		fmt.Printf("🔄 Field mapping: %s -> %s\n", field, mappedField)
	}

	// Determine primitive type based on modifiers
	primitiveType := PrimitiveEquals
	caseSensitive := false

	if len(fieldParts) > 1 {
		for _, modifier := range fieldParts[1:] {
			switch strings.ToLower(modifier) {
			case "contains":
				primitiveType = PrimitiveContains
			case "startswith":
				primitiveType = PrimitiveStartsWith
			case "endswith":
				primitiveType = PrimitiveEndsWith
			case "re", "regex":
				primitiveType = PrimitiveRegex
			case "gt":
				primitiveType = PrimitiveGreater
			case "lt":
				primitiveType = PrimitiveLess
			}
		}
	}

	// Create primitive ID for caching
	primitiveID := fmt.Sprintf("%s_%s_%v", mappedField, string(primitiveType), value)

	// Check cache
	if cached, exists := c.primitiveCache[primitiveID]; exists {
		return cached, nil
	}

	primitive := &Primitive{
		ID:            primitiveID,
		Type:          primitiveType,
		Field:         mappedField,
		Value:         value,
		CaseSensitive: caseSensitive,
		Literals:      make([]string, 0),
	}

	// Handle different value types
	switch v := value.(type) {
	case string:
		primitive.Value = v
		// Extract literals for prefiltering
		if primitiveType == PrimitiveContains || primitiveType == PrimitiveEquals ||
			primitiveType == PrimitiveEndsWith || primitiveType == PrimitiveStartsWith {
			primitive.Literals = append(primitive.Literals, v)
			fmt.Printf("🔍 Literal extracted: '%s' from field '%s' type '%s'\n", v, mappedField, primitiveType)
		}

		// Compile regex if needed
		if primitiveType == PrimitiveRegex {
			compiledRegex, err := regexp.Compile(v)
			if err != nil {
				return nil, fmt.Errorf("invalid regex in field %s: %w", originalField, err)
			}
			primitive.CompiledRegex = compiledRegex
		}

	case []interface{}:
		primitive.Values = v
		primitive.Type = PrimitiveIn

		// Extract string literals
		for _, item := range v {
			if str, ok := item.(string); ok {
				primitive.Literals = append(primitive.Literals, str)
			}
		}

	case int, int64, float64:
		primitive.Value = v

	case nil:
		primitive.Type = PrimitiveExists

	default:
		return nil, fmt.Errorf("unsupported value type for field %s: %T", originalField, value)
	}

	// Cache primitive
	c.primitiveCache[primitiveID] = primitive

	return primitive, nil
}

// parseCondition parse condition string thành DAG tree theo cawalch/sigma-engine pattern
func (c *Compiler) parseCondition(condition string, selections map[string]*DAGNode) (*DAGNode, error) {
	condition = strings.TrimSpace(condition)

	// Handle parentheses first (highest precedence)
	if strings.HasPrefix(condition, "(") && strings.HasSuffix(condition, ")") {
		innerCondition := condition[1 : len(condition)-1]
		return c.parseCondition(innerCondition, selections)
	}

	// Handle complex conditions with parentheses
	if strings.Contains(condition, "(") {
		return c.parseComplexCondition(condition, selections)
	}

	// Handle single selection
	if node, exists := selections[condition]; exists {
		return node, nil
	}

	// Handle "1 of selection_*" pattern (OR of all selections matching pattern)
	if strings.HasPrefix(condition, "1 of ") {
		pattern := strings.TrimSpace(condition[5:])
		return c.parseOfPattern(pattern, selections, false) // false = OR (any match)
	}

	// Handle "all of selection_*" pattern (AND of all selections matching pattern)
	if strings.HasPrefix(condition, "all of ") {
		pattern := strings.TrimSpace(condition[7:])
		return c.parseOfPattern(pattern, selections, true) // true = AND (all match)
	}

	// Handle "any of them" pattern
	if condition == "any of them" || condition == "1 of them" {
		return c.parseOfPattern("*", selections, false)
	}

	// Handle "all of them" pattern
	if condition == "all of them" {
		return c.parseOfPattern("*", selections, true)
	}

	// Handle NOT operation
	if strings.HasPrefix(condition, "not ") {
		innerCondition := strings.TrimSpace(condition[4:])
		innerNode, err := c.parseCondition(innerCondition, selections)
		if err != nil {
			return nil, err
		}

		return &DAGNode{
			ID:       generateNodeID(),
			Type:     NodeNot,
			Children: []*DAGNode{innerNode},
		}, nil
	}

	// Handle AND operation
	if strings.Contains(condition, " and ") {
		parts := strings.Split(condition, " and ")
		children := make([]*DAGNode, 0, len(parts))

		for _, part := range parts {
			childNode, err := c.parseCondition(strings.TrimSpace(part), selections)
			if err != nil {
				return nil, err
			}
			children = append(children, childNode)
		}

		andNode := &DAGNode{
			ID:       generateNodeID(),
			Type:     NodeAnd,
			Children: children,
		}

		// Set parent references
		for _, child := range children {
			child.Parent = andNode
		}

		return andNode, nil
	}

	// Handle OR operation
	if strings.Contains(condition, " or ") {
		parts := strings.Split(condition, " or ")
		children := make([]*DAGNode, 0, len(parts))

		for _, part := range parts {
			childNode, err := c.parseCondition(strings.TrimSpace(part), selections)
			if err != nil {
				return nil, err
			}
			children = append(children, childNode)
		}

		orNode := &DAGNode{
			ID:       generateNodeID(),
			Type:     NodeOr,
			Children: children,
		}

		// Set parent references
		for _, child := range children {
			child.Parent = orNode
		}

		return orNode, nil
	}

	return nil, fmt.Errorf("unsupported condition: %s", condition)
}

// parseComplexCondition xử lý conditions với parentheses theo cawalch pattern
func (c *Compiler) parseComplexCondition(condition string, selections map[string]*DAGNode) (*DAGNode, error) {
	// For now, handle the specific pattern: (a or b or c) and not d
	// More complex parsing can be added later if needed

	// Find the main AND/OR operator outside parentheses
	parenLevel := 0
	var mainOp string
	var mainOpPos int

	for i, char := range condition {
		switch char {
		case '(':
			parenLevel++
		case ')':
			parenLevel--
		case ' ':
			if parenLevel == 0 {
				// Check for operators at this level
				if i+4 < len(condition) && condition[i:i+5] == " and " {
					mainOp = "and"
					mainOpPos = i
					break
				}
				if i+3 < len(condition) && condition[i:i+4] == " or " {
					mainOp = "or"
					mainOpPos = i
					break
				}
			}
		}
		if mainOp != "" {
			break
		}
	}

	if mainOp != "" {
		leftPart := strings.TrimSpace(condition[:mainOpPos])
		rightPart := strings.TrimSpace(condition[mainOpPos+len(" "+mainOp+" "):])

		leftNode, err := c.parseCondition(leftPart, selections)
		if err != nil {
			return nil, err
		}

		rightNode, err := c.parseCondition(rightPart, selections)
		if err != nil {
			return nil, err
		}

		var nodeType DAGNodeType
		if mainOp == "and" {
			nodeType = NodeAnd
		} else {
			nodeType = NodeOr
		}

		resultNode := &DAGNode{
			ID:       generateNodeID(),
			Type:     nodeType,
			Children: []*DAGNode{leftNode, rightNode},
		}

		// Set parent references
		leftNode.Parent = resultNode
		rightNode.Parent = resultNode

		return resultNode, nil
	}

	return nil, fmt.Errorf("unsupported complex condition: %s", condition)
}

// parseOfPattern handles "of" patterns like "1 of selection_*" or "all of selection_*"
func (c *Compiler) parseOfPattern(pattern string, selections map[string]*DAGNode, isAnd bool) (*DAGNode, error) {
	var matchingNodes []*DAGNode

	if pattern == "*" {
		// Match all selections
		for _, node := range selections {
			matchingNodes = append(matchingNodes, node)
		}
	} else if strings.HasSuffix(pattern, "*") {
		// Pattern matching
		prefix := strings.TrimSuffix(pattern, "*")
		for name, node := range selections {
			if strings.HasPrefix(name, prefix) {
				matchingNodes = append(matchingNodes, node)
			}
		}
	} else {
		// Exact match
		if node, exists := selections[pattern]; exists {
			matchingNodes = append(matchingNodes, node)
		}
	}

	if len(matchingNodes) == 0 {
		return nil, fmt.Errorf("no selections match pattern: %s", pattern)
	}

	if len(matchingNodes) == 1 {
		return matchingNodes[0], nil
	}

	// Create AND or OR node for multiple matches
	var nodeType DAGNodeType
	if isAnd {
		nodeType = NodeAnd
	} else {
		nodeType = NodeOr
	}

	resultNode := &DAGNode{
		ID:       generateNodeID(),
		Type:     nodeType,
		Children: matchingNodes,
	}

	// Set parent references
	for _, child := range matchingNodes {
		child.Parent = resultNode
	}

	return resultNode, nil
}

// getConditionString extract condition string from detection
func getConditionString(detection map[string]interface{}) string {
	if condition, exists := detection["condition"]; exists {
		if condStr, ok := condition.(string); ok {
			return condStr
		}
	}
	return ""
}

// generateNodeID tạo unique node ID
var nodeCounter int

func generateNodeID() string {
	nodeCounter++
	return fmt.Sprintf("node_%d", nodeCounter)
}
