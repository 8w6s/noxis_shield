package intelligence

import (
	"strings"
	"sync"
)

// ASNInfo holds ASN analysis data
type ASNInfo struct {
	ASN           uint
	Organization  string
	IsHosting     bool
	IsResidential bool
	IsCDN         bool
	IsEducation   bool
	IsGovernment  bool
	RiskLevel     string // low, medium, high
	TrustScore    float64
}

// ASNAnalyzer performs ASN-based analysis
type ASNAnalyzer struct {
	cache sync.Map // map[string]*ASNInfo
}

// NewASNAnalyzer creates a new ASN analyzer
func NewASNAnalyzer() *ASNAnalyzer {
	return &ASNAnalyzer{}
}

// Analyze performs ASN analysis for an IP
func (a *ASNAnalyzer) Analyze(ip string, geo *GeoResult) *ASNInfo {
	// Check cache
	if cached, ok := a.cache.Load(ip); ok {
		return cached.(*ASNInfo)
	}

	info := &ASNInfo{
		RiskLevel:  "low",
		TrustScore: 70,
	}

	// Use GeoIP ASN data if available
	if geo != nil && geo.ASN > 0 {
		info.ASN = geo.ASN
		info.Organization = geo.ASNOrg
	}

	if info.Organization != "" {
		orgLower := strings.ToLower(info.Organization)
		info.classifyOrganization(orgLower)
	}

	a.cache.Store(ip, info)
	return info
}

// classifyOrganization classifies the ASN organization
func (info *ASNInfo) classifyOrganization(orgLower string) {
	// --- Hosting/Cloud Providers (high risk for DDoS) ---
	hostingProviders := []string{
		"digitalocean", "amazon", "aws", "google cloud", "gcp",
		"microsoft azure", "azure", "ovh", "hetzner", "linode",
		"vultr", "choopa", "contabo", "hostinger", "godaddy",
		"leaseweb", "phoenixnap", "rackspace", "scaleway",
		"upcloud", "kamatera", "ionos", "aruba", "hostway",
		"quadranet", "psychz", "colocrossing", "buyvm",
		"ramnode", "greencloudvps", "turnkey internet",
		"alibaba cloud", "tencent cloud", "huawei cloud",
		"oracle cloud", "ibm cloud", "softlayer",
	}
	for _, provider := range hostingProviders {
		if strings.Contains(orgLower, provider) {
			info.IsHosting = true
			info.RiskLevel = "medium"
			info.TrustScore = 35
			return
		}
	}

	// --- CDN Providers (legitimate, but sometimes used for attacks) ---
	cdnProviders := []string{
		"cloudflare", "fastly", "akamai", "incapsula",
		"imperva", "sucuri", "stackpath", "keycdn",
		"bunny", "cdn77", "limelight", "edgecast",
	}
	for _, cdn := range cdnProviders {
		if strings.Contains(orgLower, cdn) {
			info.IsCDN = true
			info.RiskLevel = "low"
			info.TrustScore = 75
			return
		}
	}

	// --- Known High-Risk ASNs (bulletproof hosting) ---
	highRiskProviders := []string{
		"combahton", "blazing", "sharktech", "fdc servers",
		"dacentec", "quasi networks", "serverius",
		"ecatel", "lucky", "10vps", "vpsville",
		"colo4", "webhosting24", "kuroit",
	}
	for _, risky := range highRiskProviders {
		if strings.Contains(orgLower, risky) {
			info.IsHosting = true
			info.RiskLevel = "high"
			info.TrustScore = 10
			return
		}
	}

	// --- Educational/Government (very trustworthy) ---
	eduKeywords := []string{"university", "college", "edu", "school", "academic", "research"}
	for _, kw := range eduKeywords {
		if strings.Contains(orgLower, kw) {
			info.IsEducation = true
			info.RiskLevel = "low"
			info.TrustScore = 90
			return
		}
	}

	govKeywords := []string{"government", "ministry", "federal", "military", "defense", "state of"}
	for _, kw := range govKeywords {
		if strings.Contains(orgLower, kw) {
			info.IsGovernment = true
			info.RiskLevel = "low"
			info.TrustScore = 95
			return
		}
	}

	// --- ISPs (generally trustworthy — residential traffic) ---
	ispKeywords := []string{
		"telecom", "telecomunicazioni", "communications",
		"internet service", "broadband", "fiber",
		"mobile", "wireless", "cellular",
		"cable", "netcol", "comcast", "verizon",
		"at&t", "deutsche telekom", "vodafone",
		"telefonica", "orange", "t-mobile",
		"viettel", "vnpt", "fpt telecom", "mobifone",
	}
	for _, kw := range ispKeywords {
		if strings.Contains(orgLower, kw) {
			info.IsResidential = true
			info.RiskLevel = "low"
			info.TrustScore = 80
			return
		}
	}

	// Default: unknown organization
	info.IsResidential = true
	info.TrustScore = 65
}

// CleanupCache clears the ASN cache
func (a *ASNAnalyzer) CleanupCache() {
	a.cache = sync.Map{}
}
