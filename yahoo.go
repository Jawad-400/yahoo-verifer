package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ============================
// DATA STRUCTURES
// ============================

// VerificationResult represents the API response
type VerificationResult struct {
	Email              string  `json:"email"`
	Domain             string  `json:"domain"`
	Username           string  `json:"username"`
	OverallScore       float64 `json:"overall_score"`
	IsLikelyValid      bool    `json:"is_likely_valid"`
	Confidence         string  `json:"confidence"` // high, medium, low
	PatternAnalysis    `json:"pattern_analysis"`
	DomainReputation   `json:"domain_reputation"`
	SimilarityAnalysis `json:"similarity_analysis"`
	FreshnessScore     float64 `json:"freshness_score"`
	Recommendation     string  `json:"recommendation"`
}

// PatternAnalysis for username patterns
type PatternAnalysis struct {
	UsernamePattern string  `json:"username_pattern"`
	IsRandom        bool    `json:"is_random"`
	IsRoleBased     bool    `json:"is_role_based"`
	IsCommonPattern bool    `json:"is_common_pattern"`
	PatternScore    float64 `json:"pattern_score"`
	LengthScore     float64 `json:"length_score"`
	ComplexityScore float64 `json:"complexity_score"`
}

// DomainReputation for domain scoring
type DomainReputation struct {
	Domain             string    `json:"domain"`
	TotalVerifications int       `json:"total_verifications"`
	SuccessRate        float64   `json:"success_rate"`
	BounceRate         float64   `json:"bounce_rate"`
	LastSeen           time.Time `json:"last_seen"`
	AgeScore           float64   `json:"age_score"`
	ReputationScore    float64   `json:"reputation_score"`
}

// SimilarityAnalysis for comparing with known patterns
type SimilarityAnalysis struct {
	SimilarEmailsFound int      `json:"similar_emails_found"`
	SimilarPatterns    []string `json:"similar_patterns"`
	AverageSimilarity  float64  `json:"average_similarity"`
	ClusterScore       float64  `json:"cluster_score"`
}

// HistoricalRecord tracks verification history
type HistoricalRecord struct {
	Email      string    `json:"email"`
	Domain     string    `json:"domain"`
	Username   string    `json:"username"`
	IsValid    bool      `json:"is_valid"`
	VerifiedAt time.Time `json:"verified_at"`
	Source     string    `json:"source"` // api, bounce, user_report
	Confidence float64   `json:"confidence"`
}

// YahooPattern represents Yahoo-specific patterns
type YahooPattern struct {
	ValidPatterns   []PatternRule `json:"valid_patterns"`
	InvalidPatterns []PatternRule `json:"invalid_patterns"`
	RoleAccounts    []string      `json:"role_accounts"`
	CommonUsernames []string      `json:"common_usernames"`
}

// PatternRule for pattern matching
type PatternRule struct {
	Pattern string  `json:"pattern"`
	Score   float64 `json:"score"`
	Reason  string  `json:"reason"`
}

// ============================
// VERIFICATION ENGINE
// ============================

type VerificationEngine struct {
	mu              sync.RWMutex
	historicalData  map[string]HistoricalRecord
	domainStats     map[string]DomainReputation
	yahooPatterns   YahooPattern
	similarityCache map[string][]string
}

// NewVerificationEngine creates a new engine
func NewVerificationEngine() *VerificationEngine {
	engine := &VerificationEngine{
		historicalData:  make(map[string]HistoricalRecord),
		domainStats:     make(map[string]DomainReputation),
		similarityCache: make(map[string][]string),
	}

	// Load Yahoo patterns
	engine.loadYahooPatterns()

	// Load historical data if exists
	engine.loadHistoricalData()

	return engine
}

// Helper for random number (for sample data)
func randInt(min, max int) int {
	return min + int(time.Now().UnixNano())%(max-min+1)
}

// ============================
// HELPER FUNCTIONS
// ============================

func extractEmailParts(email string) (username, domain string) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func extractUsername(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func classifyUsernamePattern(username string) string {
	if matched, _ := regexp.MatchString(`^[a-z]+\.[a-z]+$`, strings.ToLower(username)); matched {
		return "first.last"
	}
	if matched, _ := regexp.MatchString(`^[a-z]+_[a-z]+$`, strings.ToLower(username)); matched {
		return "first_last"
	}
	if matched, _ := regexp.MatchString(`^[a-z]+[0-9]+$`, strings.ToLower(username)); matched {
		return "name_numbers"
	}
	if matched, _ := regexp.MatchString(`^[0-9]+$`, username); matched {
		return "all_numbers"
	}
	return "other"
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// ============================
// PATTERN ANALYSIS
// ============================

func (ve *VerificationEngine) analyzePatterns(email string) PatternAnalysis {
	username, _ := extractEmailParts(email)
	analysis := PatternAnalysis{
		UsernamePattern: classifyUsernamePattern(username),
	}

	// Check if random
	analysis.IsRandom = ve.isRandomUsername(username)

	// Check if role-based
	analysis.IsRoleBased = ve.isRoleBasedUsername(username)

	// Check if common pattern
	analysis.IsCommonPattern = ve.isCommonUsernamePattern(username)

	// Calculate pattern score
	analysis.PatternScore = ve.calculatePatternScore(username)

	// Length score (Yahoo: 4-32 chars)
	analysis.LengthScore = ve.calculateLengthScore(username)

	// Complexity score
	analysis.ComplexityScore = ve.calculateComplexityScore(username)

	return analysis
}

// Check if username appears random
func (ve *VerificationEngine) isRandomUsername(username string) bool {
	// Check for sequences of numbers
	if matched, _ := regexp.MatchString(`\d{6,}`, username); matched {
		return true
	}

	// Check for random letter sequences
	if matched, _ := regexp.MatchString(`[a-z]{10,}[0-9]{3,}`, strings.ToLower(username)); matched {
		return true
	}

	// Check for mixed patterns that look generated
	if matched, _ := regexp.MatchString(`^[a-z]+\d+[a-z]+\d+$`, strings.ToLower(username)); matched {
		return true
	}

	return false
}

// Check if role-based account
func (ve *VerificationEngine) isRoleBasedUsername(username string) bool {
	username = strings.ToLower(username)
	for _, role := range ve.yahooPatterns.RoleAccounts {
		if strings.Contains(username, role) {
			return true
		}
	}
	return false
}

// Calculate pattern score based on Yahoo patterns
func (ve *VerificationEngine) calculatePatternScore(username string) float64 {
	score := 0.5 // Neutral start

	username = strings.ToLower(username)

	// Check valid patterns
	for _, pattern := range ve.yahooPatterns.ValidPatterns {
		if matched, _ := regexp.MatchString(pattern.Pattern, username); matched {
			score += pattern.Score
		}
	}

	// Check invalid patterns
	for _, pattern := range ve.yahooPatterns.InvalidPatterns {
		if matched, _ := regexp.MatchString(pattern.Pattern, username); matched {
			score += pattern.Score // Negative scores
		}
	}

	return math.Max(0, math.Min(1, score))
}

// ============================
// DOMAIN REPUTATION
// ============================

func (ve *VerificationEngine) analyzeDomainReputation(domain string) DomainReputation {
	ve.mu.RLock()
	defer ve.mu.RUnlock()

	if stats, exists := ve.domainStats[domain]; exists {
		// Calculate freshness
		stats.AgeScore = ve.calculateAgeScore(stats.LastSeen)
		return stats
	}

	// Default for new domains
	return DomainReputation{
		Domain:          domain,
		SuccessRate:     0.5, // Unknown
		ReputationScore: 0.5,
		AgeScore:        0.3, // New domain
		LastSeen:        time.Now(),
	}
}

// Time-decay algorithm: addresses get "stale" over time
func (ve *VerificationEngine) calculateAgeScore(lastSeen time.Time) float64 {
	daysSince := time.Since(lastSeen).Hours() / 24

	// Exponential decay: score decreases over time
	decayRate := 0.1 // 10% decay per month
	months := daysSince / 30

	freshness := math.Exp(-decayRate * months)
	return math.Max(0.1, math.Min(1.0, freshness))
}

// ============================
// SIMILARITY ANALYSIS
// ============================

func (ve *VerificationEngine) analyzeSimilarity(email string) SimilarityAnalysis {
	username, domain := extractEmailParts(email)
	analysis := SimilarityAnalysis{}

	ve.mu.RLock()
	defer ve.mu.RUnlock()

	// Find similar emails in history
	var similarEmails []string
	for histEmail := range ve.historicalData {
		if extractDomain(histEmail) != domain {
			continue
		}

		histUsername := extractUsername(histEmail)
		similarity := ve.calculateUsernameSimilarity(username, histUsername)

		if similarity > 0.7 { // 70% similarity threshold
			similarEmails = append(similarEmails, histEmail)
		}
	}

	analysis.SimilarEmailsFound = len(similarEmails)
	analysis.SimilarPatterns = similarEmails

	// Calculate cluster score (more similar emails = more suspicious)
	if len(similarEmails) > 0 {
		analysis.ClusterScore = 1.0 / (1.0 + float64(len(similarEmails))/10.0)
	} else {
		analysis.ClusterScore = 0.8 // No similar emails is good
	}

	return analysis
}

// Calculate similarity between two usernames
func (ve *VerificationEngine) calculateUsernameSimilarity(username1, username2 string) float64 {
	// Simple Levenshtein distance-based similarity
	distance := levenshteinDistance(username1, username2)
	maxLen := math.Max(float64(len(username1)), float64(len(username2)))

	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - float64(distance)/maxLen
}

// Levenshtein distance implementation
func levenshteinDistance(s1, s2 string) int {
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	if len(s1) < len(s2) {
		s1, s2 = s2, s1
	}

	if len(s2) == 0 {
		return len(s1)
	}

	previousRow := make([]int, len(s2)+1)
	for i := range previousRow {
		previousRow[i] = i
	}

	for i, c1 := range s1 {
		currentRow := []int{i + 1}

		for j, c2 := range s2 {
			insertions := previousRow[j+1] + 1
			deletions := currentRow[j] + 1
			substitutions := previousRow[j]
			if c1 != c2 {
				substitutions++
			}
			currentRow = append(currentRow, min(insertions, deletions, substitutions))
		}

		previousRow = currentRow
	}

	return previousRow[len(previousRow)-1]
}

// ============================
// OVERALL VERIFICATION
// ============================

func (ve *VerificationEngine) VerifyEmail(email string) VerificationResult {
	username, domain := extractEmailParts(email)

	// 1. Pattern Analysis
	patternAnalysis := ve.analyzePatterns(email)

	// 2. Domain Reputation
	domainReputation := ve.analyzeDomainReputation(domain)

	// 3. Similarity Analysis
	similarityAnalysis := ve.analyzeSimilarity(email)

	// 4. Time-decay freshness
	freshnessScore := ve.calculateAgeScore(time.Now())

	// 5. Calculate overall score (weighted average)
	overallScore := ve.calculateOverallScore(
		patternAnalysis,
		domainReputation,
		similarityAnalysis,
		freshnessScore,
	)

	// 6. Determine if likely valid
	isLikelyValid := overallScore >= 0.6

	// 7. Confidence level
	confidence := "low"
	if overallScore >= 0.8 {
		confidence = "high"
	} else if overallScore >= 0.6 {
		confidence = "medium"
	}

	// 8. Recommendation
	recommendation := ve.generateRecommendation(overallScore, patternAnalysis, domainReputation)

	// 9. Store this verification in history
	ve.recordVerification(email, isLikelyValid, overallScore)

	return VerificationResult{
		Email:              email,
		Domain:             domain,
		Username:           username,
		OverallScore:       overallScore,
		IsLikelyValid:      isLikelyValid,
		Confidence:         confidence,
		PatternAnalysis:    patternAnalysis,
		DomainReputation:   domainReputation,
		SimilarityAnalysis: similarityAnalysis,
		FreshnessScore:     freshnessScore,
		Recommendation:     recommendation,
	}
}

// Calculate weighted overall score
func (ve *VerificationEngine) calculateOverallScore(
	patterns PatternAnalysis,
	domain DomainReputation,
	similarity SimilarityAnalysis,
	freshness float64,
) float64 {
	weights := map[string]float64{
		"pattern":    0.35, // 35% weight to patterns
		"domain":     0.25, // 25% to domain reputation
		"similarity": 0.20, // 20% to similarity
		"freshness":  0.20, // 20% to freshness
	}

	score := patterns.PatternScore*weights["pattern"] +
		domain.ReputationScore*weights["domain"] +
		similarity.ClusterScore*weights["similarity"] +
		freshness*weights["freshness"]

	return math.Max(0, math.Min(1, score))
}

// Generate recommendation based on analysis
func (ve *VerificationEngine) generateRecommendation(score float64, patterns PatternAnalysis, domain DomainReputation) string {
	if score < 0.4 {
		return "REJECT: High risk of being invalid or spam"
	} else if score < 0.6 {
		return "REVIEW: Requires double opt-in verification"
	} else if patterns.IsRoleBased {
		return "ACCEPT_WITH_CAUTION: Role-based account, may have low engagement"
	} else if domain.SuccessRate < 0.3 {
		return "ACCEPT_WITH_VERIFICATION: Domain has low success rate"
	} else {
		return "ACCEPT: Likely valid email address"
	}
}

// ============================
// DATA PERSISTENCE
// ============================

// Load Yahoo patterns from JSON
func (ve *VerificationEngine) loadYahooPatterns() {
	// Default patterns if file doesn't exist
	ve.yahooPatterns = YahooPattern{
		ValidPatterns: []PatternRule{
			{Pattern: `^[a-z]{4,15}$`, Score: 0.2, Reason: "Simple username"},
			{Pattern: `^[a-z]+\.[a-z]+$`, Score: 0.3, Reason: "First.Last format"},
			{Pattern: `^[a-z]+[0-9]{1,3}$`, Score: 0.1, Reason: "Name with few numbers"},
			{Pattern: `^[a-z]+_[a-z]+$`, Score: 0.2, Reason: "First_Last format"},
		},
		InvalidPatterns: []PatternRule{
			{Pattern: `^[0-9]{6,}$`, Score: -0.5, Reason: "All numbers"},
			{Pattern: `^test`, Score: -0.4, Reason: "Test account"},
			{Pattern: `^temp`, Score: -0.6, Reason: "Temporary account"},
			{Pattern: `^demo`, Score: -0.4, Reason: "Demo account"},
			{Pattern: `[^a-z0-9._-]`, Score: -0.3, Reason: "Invalid characters"},
			{Pattern: `^[a-z]{20,}$`, Score: -0.3, Reason: "Too long"},
			{Pattern: `_+`, Score: -0.2, Reason: "Multiple underscores"},
			{Pattern: `\.{2,}`, Score: -0.2, Reason: "Multiple dots"},
		},
		RoleAccounts: []string{
			"admin", "administrator", "info", "support",
			"help", "contact", "sales", "marketing",
			"webmaster", "postmaster", "noreply",
		},
		CommonUsernames: []string{
			"john", "jane", "mike", "david", "sarah",
			"test", "demo", "info", "support", "admin",
		},
	}
}

// Load historical data from file
func (ve *VerificationEngine) loadHistoricalData() {
	// In a real app, load from JSON file or database
	// For now, we'll seed with some sample data
	ve.mu.Lock()
	defer ve.mu.Unlock()

	// Sample historical data for Yahoo
	sampleEmails := []string{
		"john.doe@yahoo.com",
		"jane.smith@yahoo.com",
		"test123@yahoo.com",
		"admin@yahoo.com",
		"support@yahoo.com",
		"randomuser2023@yahoo.com",
		"user456789@yahoo.com",
	}

	for _, email := range sampleEmails {
		ve.historicalData[email] = HistoricalRecord{
			Email:      email,
			Domain:     "yahoo.com",
			Username:   extractUsername(email),
			IsValid:    !strings.Contains(email, "test") && !strings.Contains(email, "admin"),
			VerifiedAt: time.Now().Add(-time.Duration(randInt(1, 180)) * 24 * time.Hour),
			Source:     "api",
			Confidence: 0.8,
		}
	}
}

// Record a new verification
func (ve *VerificationEngine) recordVerification(email string, isValid bool, confidence float64) {
	ve.mu.Lock()
	defer ve.mu.Unlock()

	username, domain := extractEmailParts(email)

	// Update historical data
	ve.historicalData[email] = HistoricalRecord{
		Email:      email,
		Domain:     domain,
		Username:   username,
		IsValid:    isValid,
		VerifiedAt: time.Now(),
		Source:     "api",
		Confidence: confidence,
	}

	// Update domain stats
	stats := ve.domainStats[domain]
	stats.Domain = domain
	stats.TotalVerifications++
	if isValid {
		stats.SuccessRate = (stats.SuccessRate*float64(stats.TotalVerifications-1) + 1.0) / float64(stats.TotalVerifications)
	} else {
		stats.BounceRate = (stats.BounceRate*float64(stats.TotalVerifications-1) + 1.0) / float64(stats.TotalVerifications)
	}
	stats.LastSeen = time.Now()
	stats.ReputationScore = stats.SuccessRate*0.7 + (1-stats.BounceRate)*0.3
	ve.domainStats[domain] = stats

	// Save to file periodically (in production)
}

func (ve *VerificationEngine) isCommonUsernamePattern(username string) bool {
	username = strings.ToLower(username)
	for _, common := range ve.yahooPatterns.CommonUsernames {
		if username == common {
			return true
		}
	}
	return false
}

func (ve *VerificationEngine) calculateLengthScore(username string) float64 {
	length := len(username)
	// Yahoo allows 4-32 characters
	if length >= 4 && length <= 32 {
		if length >= 6 && length <= 20 {
			return 1.0 // Ideal length
		}
		return 0.7 // Acceptable but not ideal
	}
	return 0.3 // Too short or too long
}

func (ve *VerificationEngine) calculateComplexityScore(username string) float64 {
	score := 0.0

	// Check for mixed case
	if strings.ToLower(username) != username && strings.ToUpper(username) != username {
		score += 0.2
	}

	// Check for numbers
	if matched, _ := regexp.MatchString(`[0-9]`, username); matched {
		score += 0.2
	}

	// Check for special characters (Yahoo allows ._-)
	if matched, _ := regexp.MatchString(`[._-]`, username); matched {
		score += 0.1
	}

	// Penalty for too many special chars
	if strings.Count(username, ".") > 2 || strings.Count(username, "_") > 2 {
		score -= 0.2
	}

	return math.Max(0, math.Min(1, 0.5+score))
}

// ============================
// HTTP SERVER
// ============================

type VerifyRequest struct {
	Email string `json:"email"`
}

type VerifyResponse struct {
	Success bool               `json:"success"`
	Data    VerificationResult `json:"data,omitempty"`
	Error   string             `json:"error,omitempty"`
}

func main() {
	// Initialize verification engine
	engine := NewVerificationEngine()

	// HTTP Handlers
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			response := VerifyResponse{
				Success: false,
				Error:   "Invalid JSON request",
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		if req.Email == "" {
			response := VerifyResponse{
				Success: false,
				Error:   "Email is required",
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Verify the email
		result := engine.VerifyEmail(req.Email)

		response := VerifyResponse{
			Success: true,
			Data:    result,
		}

		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":             "running",
			"engine":             "Historical Pattern Verifier",
			"version":            "1.0.0",
			"domains_tracked":    len(engine.domainStats),
			"historical_records": len(engine.historicalData),
		})
	})

	// Start server
	port := ":8081"
	fmt.Printf("🚀 Email Verification API running on http://localhost%s\n", port)
	fmt.Printf("📊 Endpoints:\n")
	fmt.Printf("  POST http://localhost%s/verify - Verify an email\n", port)
	fmt.Printf("  GET  http://localhost%s/stats - Get API stats\n", port)

	log.Fatal(http.ListenAndServe(port, nil))
}
