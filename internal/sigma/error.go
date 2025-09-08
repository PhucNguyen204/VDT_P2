package sigma

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

// Error types based on cawalch/sigma-engine error handling system

// SigmaError - Base error interface for all SIGMA engine errors
type SigmaError interface {
	error
	ErrorCode() string
	ErrorType() ErrorType
	Context() map[string]interface{}
	Severity() ErrorSeverity
	Retryable() bool
	Timestamp() time.Time
	StackTrace() []string
}

// ErrorType - Categories of errors in the SIGMA engine
type ErrorType string

const (
	// Compilation errors
	ErrorTypeCompilation  ErrorType = "compilation"
	ErrorTypeParser       ErrorType = "parser"
	ErrorTypeValidation   ErrorType = "validation"
	ErrorTypeFieldMapping ErrorType = "field_mapping"

	// Runtime errors
	ErrorTypeExecution ErrorType = "execution"
	ErrorTypeDAG       ErrorType = "dag"
	ErrorTypeTimeout   ErrorType = "timeout"
	ErrorTypeResource  ErrorType = "resource"

	// Streaming errors
	ErrorTypeStreaming    ErrorType = "streaming"
	ErrorTypeBackpressure ErrorType = "backpressure"
	ErrorTypeBatching     ErrorType = "batching"
	ErrorTypeWorker       ErrorType = "worker"

	// System errors
	ErrorTypeSystem        ErrorType = "system"
	ErrorTypeNetwork       ErrorType = "network"
	ErrorTypeStorage       ErrorType = "storage"
	ErrorTypeConfiguration ErrorType = "configuration"

	// Internal errors
	ErrorTypeInternal ErrorType = "internal"
	ErrorTypePanic    ErrorType = "panic"
	ErrorTypeUnknown  ErrorType = "unknown"
)

// ErrorSeverity - Severity levels for errors
type ErrorSeverity string

const (
	SeverityLow      ErrorSeverity = "low"
	SeverityMedium   ErrorSeverity = "medium"
	SeverityHigh     ErrorSeverity = "high"
	SeverityCritical ErrorSeverity = "critical"
)

// BaseError - Base implementation of SigmaError
type BaseError struct {
	Code    string                 `json:"code"`
	Type    ErrorType              `json:"type"`
	Message string                 `json:"message"`
	Ctx     map[string]interface{} `json:"context"`
	Sev     ErrorSeverity          `json:"severity"`
	Retry   bool                   `json:"retryable"`
	Time    time.Time              `json:"timestamp"`
	Stack   []string               `json:"stack_trace"`
	Cause   error                  `json:"cause,omitempty"`
}

// Error - Implement error interface
func (e *BaseError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.Type, e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Type, e.Code, e.Message)
}

// ErrorCode - Get error code
func (e *BaseError) ErrorCode() string {
	return e.Code
}

// ErrorType - Get error type
func (e *BaseError) ErrorType() ErrorType {
	return e.Type
}

// Context - Get error context
func (e *BaseError) Context() map[string]interface{} {
	return e.Ctx
}

// Severity - Get error severity
func (e *BaseError) Severity() ErrorSeverity {
	return e.Sev
}

// Retryable - Check if error is retryable
func (e *BaseError) Retryable() bool {
	return e.Retry
}

// Timestamp - Get error timestamp
func (e *BaseError) Timestamp() time.Time {
	return e.Time
}

// StackTrace - Get stack trace
func (e *BaseError) StackTrace() []string {
	return e.Stack
}

// WithContext - Add context to error
func (e *BaseError) WithContext(key string, value interface{}) *BaseError {
	if e.Ctx == nil {
		e.Ctx = make(map[string]interface{})
	}
	e.Ctx[key] = value
	return e
}

// WithCause - Add underlying cause
func (e *BaseError) WithCause(cause error) *BaseError {
	e.Cause = cause
	return e
}

// Specific error types

// CompilationError - Errors during rule compilation
type CompilationError struct {
	*BaseError
	RuleID     string `json:"rule_id"`
	RuleName   string `json:"rule_name"`
	LineNumber int    `json:"line_number"`
	Column     int    `json:"column"`
}

// ExecutionError - Errors during rule execution
type ExecutionError struct {
	*BaseError
	RuleID    string      `json:"rule_id"`
	EventID   string      `json:"event_id"`
	NodeID    string      `json:"node_id"`
	EventData interface{} `json:"event_data,omitempty"`
}

// StreamingError - Errors in streaming engine
type StreamingError struct {
	*BaseError
	WorkerID   int    `json:"worker_id"`
	BatchID    string `json:"batch_id"`
	QueueSize  int    `json:"queue_size"`
	BufferSize int    `json:"buffer_size"`
}

// ResourceError - Resource-related errors
type ResourceError struct {
	*BaseError
	ResourceType string `json:"resource_type"`
	Available    int64  `json:"available"`
	Required     int64  `json:"required"`
	Limit        int64  `json:"limit"`
}

// TimeoutError - Timeout-related errors
type TimeoutError struct {
	*BaseError
	Operation string        `json:"operation"`
	Timeout   time.Duration `json:"timeout"`
	Elapsed   time.Duration `json:"elapsed"`
}

// Error constructor functions

// NewCompilationError - Create compilation error
func NewCompilationError(code, message string, ruleID string) *CompilationError {
	return &CompilationError{
		BaseError: &BaseError{
			Code:    code,
			Type:    ErrorTypeCompilation,
			Message: message,
			Sev:     SeverityHigh,
			Time:    time.Now(),
			Stack:   captureStackTrace(),
		},
		RuleID: ruleID,
	}
}

// NewExecutionError - Create execution error
func NewExecutionError(code, message string, ruleID, eventID string) *ExecutionError {
	return &ExecutionError{
		BaseError: &BaseError{
			Code:    code,
			Type:    ErrorTypeExecution,
			Message: message,
			Sev:     SeverityMedium,
			Retry:   true,
			Time:    time.Now(),
			Stack:   captureStackTrace(),
		},
		RuleID:  ruleID,
		EventID: eventID,
	}
}

// NewStreamingError - Create streaming error
func NewStreamingError(code, message string, workerID int) *StreamingError {
	return &StreamingError{
		BaseError: &BaseError{
			Code:    code,
			Type:    ErrorTypeStreaming,
			Message: message,
			Sev:     SeverityHigh,
			Retry:   true,
			Time:    time.Now(),
			Stack:   captureStackTrace(),
		},
		WorkerID: workerID,
	}
}

// NewResourceError - Create resource error
func NewResourceError(code, message, resourceType string) *ResourceError {
	return &ResourceError{
		BaseError: &BaseError{
			Code:    code,
			Type:    ErrorTypeResource,
			Message: message,
			Sev:     SeverityCritical,
			Retry:   false,
			Time:    time.Now(),
			Stack:   captureStackTrace(),
		},
		ResourceType: resourceType,
	}
}

// NewTimeoutError - Create timeout error
func NewTimeoutError(operation string, timeout, elapsed time.Duration) *TimeoutError {
	return &TimeoutError{
		BaseError: &BaseError{
			Code:    "TIMEOUT",
			Type:    ErrorTypeTimeout,
			Message: fmt.Sprintf("Operation '%s' timed out", operation),
			Sev:     SeverityMedium,
			Retry:   true,
			Time:    time.Now(),
			Stack:   captureStackTrace(),
		},
		Operation: operation,
		Timeout:   timeout,
		Elapsed:   elapsed,
	}
}

// Predefined error codes and constructors

// Compilation errors
func ErrInvalidYAML(ruleID string, cause error) *CompilationError {
	return NewCompilationError("INVALID_YAML", "Invalid YAML syntax", ruleID).WithCause(cause).(*CompilationError)
}

func ErrInvalidCondition(ruleID, condition string) *CompilationError {
	err := NewCompilationError("INVALID_CONDITION", "Invalid condition syntax", ruleID)
	err.WithContext("condition", condition)
	return err
}

func ErrFieldNotFound(ruleID, field string) *CompilationError {
	err := NewCompilationError("FIELD_NOT_FOUND", "Field not found in mapping", ruleID)
	err.WithContext("field", field)
	return err
}

func ErrUnsupportedModifier(ruleID, modifier string) *CompilationError {
	err := NewCompilationError("UNSUPPORTED_MODIFIER", "Unsupported field modifier", ruleID)
	err.WithContext("modifier", modifier)
	return err
}

// Execution errors
func ErrNodeExecution(ruleID, nodeID, eventID string, cause error) *ExecutionError {
	err := NewExecutionError("NODE_EXECUTION", "Node execution failed", ruleID, eventID)
	err.WithContext("node_id", nodeID)
	err.WithCause(cause)
	return err
}

func ErrRegexCompilation(ruleID, pattern string, cause error) *ExecutionError {
	err := NewExecutionError("REGEX_COMPILATION", "Regex pattern compilation failed", ruleID, "")
	err.WithContext("pattern", pattern)
	err.WithCause(cause)
	return err
}

func ErrTypeConversion(ruleID, eventID string, expected, actual interface{}) *ExecutionError {
	err := NewExecutionError("TYPE_CONVERSION", "Type conversion failed", ruleID, eventID)
	err.WithContext("expected", expected)
	err.WithContext("actual", actual)
	return err
}

// Streaming errors
func ErrWorkerPanic(workerID int, cause error) *StreamingError {
	err := NewStreamingError("WORKER_PANIC", "Worker panic recovered", workerID)
	err.Sev = SeverityCritical
	err.WithCause(cause)
	return err
}

func ErrQueueFull(workerID, queueSize int) *StreamingError {
	err := NewStreamingError("QUEUE_FULL", "Worker queue is full", workerID)
	err.WithContext("queue_size", queueSize)
	return err
}

func ErrBackpressureThreshold(threshold, current int) *StreamingError {
	err := NewStreamingError("BACKPRESSURE_THRESHOLD", "Backpressure threshold exceeded", -1)
	err.Type = ErrorTypeBackpressure
	err.WithContext("threshold", threshold)
	err.WithContext("current", current)
	return err
}

func ErrBatchProcessing(batchID string, size int, cause error) *StreamingError {
	err := NewStreamingError("BATCH_PROCESSING", "Batch processing failed", -1)
	err.Type = ErrorTypeBatching
	err.WithContext("batch_id", batchID)
	err.WithContext("batch_size", size)
	err.WithCause(cause)
	return err
}

// Resource errors
func ErrMemoryLimit(available, required, limit int64) *ResourceError {
	err := NewResourceError("MEMORY_LIMIT", "Memory limit exceeded", "memory")
	err.Available = available
	err.Required = required
	err.Limit = limit
	return err
}

func ErrCPULimit(usage float64) *ResourceError {
	err := NewResourceError("CPU_LIMIT", "CPU usage limit exceeded", "cpu")
	err.WithContext("usage", usage)
	return err
}

func ErrFileDescriptorLimit(current, limit int) *ResourceError {
	err := NewResourceError("FD_LIMIT", "File descriptor limit exceeded", "file_descriptors")
	err.Available = int64(limit - current)
	err.Required = 1
	err.Limit = int64(limit)
	return err
}

// System errors
func ErrConfigValidation(field, value string) *BaseError {
	err := &BaseError{
		Code:    "CONFIG_VALIDATION",
		Type:    ErrorTypeConfiguration,
		Message: fmt.Sprintf("Configuration validation failed for field '%s'", field),
		Sev:     SeverityHigh,
		Time:    time.Now(),
		Stack:   captureStackTrace(),
	}
	err.WithContext("field", field)
	err.WithContext("value", value)
	return err
}

func ErrNetworkConnection(endpoint string, cause error) *BaseError {
	err := &BaseError{
		Code:    "NETWORK_CONNECTION",
		Type:    ErrorTypeNetwork,
		Message: fmt.Sprintf("Network connection failed to '%s'", endpoint),
		Sev:     SeverityMedium,
		Retry:   true,
		Time:    time.Now(),
		Stack:   captureStackTrace(),
		Cause:   cause,
	}
	err.WithContext("endpoint", endpoint)
	return err
}

// Error aggregation and handling

// ErrorCollection - Collection of errors for batch operations
type ErrorCollection struct {
	Errors []SigmaError `json:"errors"`
	Count  int          `json:"count"`
}

// NewErrorCollection - Create new error collection
func NewErrorCollection() *ErrorCollection {
	return &ErrorCollection{
		Errors: make([]SigmaError, 0),
	}
}

// Add - Add error to collection
func (ec *ErrorCollection) Add(err SigmaError) {
	ec.Errors = append(ec.Errors, err)
	ec.Count++
}

// HasErrors - Check if collection has errors
func (ec *ErrorCollection) HasErrors() bool {
	return ec.Count > 0
}

// Error - Implement error interface
func (ec *ErrorCollection) Error() string {
	if ec.Count == 0 {
		return "no errors"
	}

	if ec.Count == 1 {
		return ec.Errors[0].Error()
	}

	return fmt.Sprintf("multiple errors (%d): %s", ec.Count, ec.Errors[0].Error())
}

// GetBySeverity - Get errors by severity
func (ec *ErrorCollection) GetBySeverity(severity ErrorSeverity) []SigmaError {
	var result []SigmaError
	for _, err := range ec.Errors {
		if err.Severity() == severity {
			result = append(result, err)
		}
	}
	return result
}

// GetByType - Get errors by type
func (ec *ErrorCollection) GetByType(errorType ErrorType) []SigmaError {
	var result []SigmaError
	for _, err := range ec.Errors {
		if err.ErrorType() == errorType {
			result = append(result, err)
		}
	}
	return result
}

// GetRetryable - Get retryable errors
func (ec *ErrorCollection) GetRetryable() []SigmaError {
	var result []SigmaError
	for _, err := range ec.Errors {
		if err.Retryable() {
			result = append(result, err)
		}
	}
	return result
}

// ErrorHandler - Interface for handling errors
type ErrorHandler interface {
	Handle(error SigmaError) error
	CanHandle(errorType ErrorType) bool
	Priority() int
}

// ErrorManager - Manages error handling and recovery
type ErrorManager struct {
	handlers []ErrorHandler
	metrics  *ErrorMetrics
}

// ErrorMetrics - Metrics for error tracking
type ErrorMetrics struct {
	TotalErrors      int64                   `json:"total_errors"`
	ErrorsByType     map[ErrorType]int64     `json:"errors_by_type"`
	ErrorsBySeverity map[ErrorSeverity]int64 `json:"errors_by_severity"`
	RetryAttempts    int64                   `json:"retry_attempts"`
	RecoveredErrors  int64                   `json:"recovered_errors"`
}

// NewErrorManager - Create new error manager
func NewErrorManager() *ErrorManager {
	return &ErrorManager{
		handlers: make([]ErrorHandler, 0),
		metrics: &ErrorMetrics{
			ErrorsByType:     make(map[ErrorType]int64),
			ErrorsBySeverity: make(map[ErrorSeverity]int64),
		},
	}
}

// RegisterHandler - Register error handler
func (em *ErrorManager) RegisterHandler(handler ErrorHandler) {
	em.handlers = append(em.handlers, handler)
}

// Handle - Handle error with registered handlers
func (em *ErrorManager) Handle(err SigmaError) error {
	em.updateMetrics(err)

	for _, handler := range em.handlers {
		if handler.CanHandle(err.ErrorType()) {
			if handlerErr := handler.Handle(err); handlerErr == nil {
				em.metrics.RecoveredErrors++
				return nil
			}
		}
	}

	return err
}

// UpdateMetrics - Update error metrics
func (em *ErrorManager) updateMetrics(err SigmaError) {
	em.metrics.TotalErrors++
	em.metrics.ErrorsByType[err.ErrorType()]++
	em.metrics.ErrorsBySeverity[err.Severity()]++
}

// Utility functions

// captureStackTrace - Capture current stack trace
func captureStackTrace() []string {
	var traces []string

	for i := 2; i < 10; i++ { // Skip current function and caller
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}

		// Simplify file path
		parts := strings.Split(file, "/")
		if len(parts) > 2 {
			file = strings.Join(parts[len(parts)-2:], "/")
		}

		traces = append(traces, fmt.Sprintf("%s:%d", file, line))
	}

	return traces
}

// WrapError - Wrap standard error as SigmaError
func WrapError(err error, errorType ErrorType, code string) SigmaError {
	if err == nil {
		return nil
	}

	// Check if already a SigmaError
	if sigmaErr, ok := err.(SigmaError); ok {
		return sigmaErr
	}

	return &BaseError{
		Code:    code,
		Type:    errorType,
		Message: err.Error(),
		Sev:     SeverityMedium,
		Time:    time.Now(),
		Stack:   captureStackTrace(),
		Cause:   err,
	}
}

// RecoverFromPanic - Recover from panic and convert to error
func RecoverFromPanic() SigmaError {
	if r := recover(); r != nil {
		message := "Unknown panic"
		if msg, ok := r.(string); ok {
			message = msg
		} else if err, ok := r.(error); ok {
			message = err.Error()
		}

		return &BaseError{
			Code:    "PANIC_RECOVERED",
			Type:    ErrorTypePanic,
			Message: message,
			Sev:     SeverityCritical,
			Time:    time.Now(),
			Stack:   captureStackTrace(),
		}
	}
	return nil
}
