package processor

import (
	"edr-server/internal/sigma"

	"github.com/sirupsen/logrus"
)

// advancedProgressiveCompilation implements async batch compilation for handling thousands of rules using cawalch/sigma-engine API
func advancedProgressiveCompilation(engine *sigma.SigmaEngine, rules []string, logger *logrus.Logger) []string {
	// Advanced batching strategy for handling thousands of rules
	batchSize := determineOptimalBatchSize(len(rules))
	workerCount := determineOptimalWorkerCount(len(rules)) // Dynamic worker scaling
	successfulRules := []string{}

	logger.WithFields(logrus.Fields{
		"batch_size":   batchSize,
		"worker_count": workerCount,
		"total_rules":  len(rules),
	}).Info("🚀 Starting advanced async batch compilation")

	// Phase 1: Parallel batch validation
	validatedBatches := asyncBatchValidation(rules, batchSize, workerCount, logger)

	// Phase 2: Collect successful rules from all batches
	for _, batch := range validatedBatches {
		successfulRules = append(successfulRules, batch...)
	}

	logger.WithFields(logrus.Fields{
		"successful_rules": len(successfulRules),
		"success_rate":     float64(len(successfulRules)) / float64(len(rules)) * 100,
	}).Info("📊 Advanced batch validation completed")

	// Phase 3: Final compilation with all successful rules
	if len(successfulRules) > 0 {
		// Use staged compilation for large rulesets
		finalRules := stagedCompilation(engine, successfulRules, logger)
		return finalRules
	}

	return successfulRules
}

// determineOptimalBatchSize calculates optimal batch size based on total rules
func determineOptimalBatchSize(totalRules int) int {
	switch {
	case totalRules >= 3000:
		return 150 // Extra large batches for 3,033 SIGMA rules
	case totalRules >= 2000:
		return 125 // Large batches for massive rulesets
	case totalRules >= 1000:
		return 100 // Medium-large batches for large rulesets
	case totalRules >= 500:
		return 75 // Medium batches
	default:
		return 50 // Standard batches for smaller rulesets
	}
}

// determineOptimalWorkerCount calculates optimal worker count based on total rules
func determineOptimalWorkerCount(totalRules int) int {
	switch {
	case totalRules >= 3000:
		return 8 // 8 workers for 3,033 SIGMA rules
	case totalRules >= 2000:
		return 6 // 6 workers for massive rulesets
	case totalRules >= 1000:
		return 4 // 4 workers for large rulesets
	default:
		return 2 // 2 workers for smaller rulesets
	}
}

// asyncBatchValidation performs parallel batch validation using goroutines
func asyncBatchValidation(rules []string, batchSize, workerCount int, logger *logrus.Logger) [][]string {
	type batchResult struct {
		index int
		rules []string
		error error
	}

	// Create batches
	batches := make([][]string, 0)
	for i := 0; i < len(rules); i += batchSize {
		end := i + batchSize
		if end > len(rules) {
			end = len(rules)
		}
		batches = append(batches, rules[i:end])
	}

	// Channel for work distribution and results
	batchChan := make(chan int, len(batches))
	resultChan := make(chan batchResult, len(batches))

	// Start workers
	for w := 0; w < workerCount; w++ {
		go func(workerId int) {
			for batchIndex := range batchChan {
				batch := batches[batchIndex]

				// Test compilation for this batch
				testEngine := sigma.NewSigmaEngine(nil, logger)
				err := testEngine.FromRules(batch)

				if err != nil {
					// If batch fails, validate individual rules
					validRules := validateIndividualRules(batch, logger)
					resultChan <- batchResult{
						index: batchIndex,
						rules: validRules,
						error: err,
					}
				} else {
					// Batch succeeded
					resultChan <- batchResult{
						index: batchIndex,
						rules: batch,
						error: nil,
					}
				}

				logger.WithFields(logrus.Fields{
					"worker_id":   workerId,
					"batch_index": batchIndex,
					"batch_size":  len(batch),
					"success":     err == nil,
				}).Debug("🔧 Async batch validation completed")
			}
		}(w)
	}

	// Send work to workers
	for i := range batches {
		batchChan <- i
	}
	close(batchChan)

	// Collect results
	validatedBatches := make([][]string, 0)
	for i := 0; i < len(batches); i++ {
		result := <-resultChan
		if len(result.rules) > 0 {
			validatedBatches = append(validatedBatches, result.rules)
		}
	}

	return validatedBatches
}

// validateIndividualRules validates rules one by one when batch fails
func validateIndividualRules(batch []string, logger *logrus.Logger) []string {
	validRules := []string{}

	for i, rule := range batch {
		testEngine := sigma.NewSigmaEngine(nil, logger)
		err := testEngine.FromRules([]string{rule})

		if err == nil {
			validRules = append(validRules, rule)
		} else {
			logger.WithFields(logrus.Fields{
				"rule_index": i,
				"error":      err.Error(),
			}).Debug("❌ Individual rule validation failed")
		}
	}

	return validRules
}

// stagedCompilation compiles large rulesets in stages to avoid memory issues
func stagedCompilation(engine *sigma.SigmaEngine, successfulRules []string, logger *logrus.Logger) []string {
	if len(successfulRules) <= 500 {
		// Small ruleset - compile directly
		err := engine.FromRules(successfulRules)
		if err != nil {
			logger.WithError(err).Warn("❌ Direct compilation failed")
			return []string{}
		}
		return successfulRules
	}

	// Large ruleset - staged compilation
	stageSize := 500
	compiledRules := []string{}

	logger.WithFields(logrus.Fields{
		"total_rules": len(successfulRules),
		"stage_size":  stageSize,
	}).Info("🔄 Starting staged compilation for large ruleset")

	for i := 0; i < len(successfulRules); i += stageSize {
		end := i + stageSize
		if end > len(successfulRules) {
			end = len(successfulRules)
		}

		stage := append(compiledRules, successfulRules[i:end]...)
		testEngine := sigma.NewSigmaEngine(nil, logger)

		err := testEngine.FromRules(stage)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"stage_start": i,
				"stage_size":  end - i,
				"error":       err.Error(),
			}).Warn("❌ Stage compilation failed, using previous stage")
			break
		}

		compiledRules = stage
		logger.WithFields(logrus.Fields{
			"stage":          (i / stageSize) + 1,
			"compiled_rules": len(compiledRules),
		}).Debug("✅ Stage compilation successful")
	}

	// Final compilation with engine
	if len(compiledRules) > 0 {
		err := engine.FromRules(compiledRules)
		if err != nil {
			logger.WithError(err).Warn("❌ Final staged compilation failed")
			return []string{}
		}
	}

	return compiledRules
}
