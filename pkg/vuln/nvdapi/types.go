package nvdapi

type CVEsResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	Cve Cve `json:"cve"`
}

type Cve struct {
	ID               string `json:"id"`
	SourceIdentifier string `json:"sourceIdentifier"`
	Published        string `json:"published"`
	LastModified     string `json:"lastModified"`
	VulnStatus       string `json:"vulnStatus"`
	EvaluatorImpact  string `json:"evaluatorImpact,omitempty"`
	Descriptions     []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics    Metrics `json:"metrics"`
	Weaknesses []struct {
		Source      string `json:"source"`
		Type        string `json:"type"`
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			Operator string     `json:"operator"`
			Negate   bool       `json:"negate"`
			CpeMatch []CpeMatch `json:"cpeMatch"`
		} `json:"nodes"`
		Operator string `json:"operator,omitempty"`
	} `json:"configurations"`
	References []struct {
		URL    string   `json:"url"`
		Source string   `json:"source"`
		Tags   []string `json:"tags,omitempty"`
	} `json:"references"`
}

type Metrics struct {
	CvssMetricV2 []struct {
		Source   string `json:"source"`
		Type     string `json:"type"`
		CvssData struct {
			Version               string  `json:"version"`
			VectorString          string  `json:"vectorString"`
			AccessVector          string  `json:"accessVector"`
			AccessComplexity      string  `json:"accessComplexity"`
			Authentication        string  `json:"authentication"`
			ConfidentialityImpact string  `json:"confidentialityImpact"`
			IntegrityImpact       string  `json:"integrityImpact"`
			AvailabilityImpact    string  `json:"availabilityImpact"`
			BaseScore             float64 `json:"baseScore"`
		} `json:"cvssData"`
		BaseSeverity            string  `json:"baseSeverity"`
		ExploitabilityScore     float64 `json:"exploitabilityScore"`
		ImpactScore             float64 `json:"impactScore"`
		AcInsufInfo             bool    `json:"acInsufInfo"`
		ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
		ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
		ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
		UserInteractionRequired bool    `json:"userInteractionRequired,omitempty"`
	} `json:"cvssMetricV2,omitempty"`
	CvssMetricV30 []struct {
		Source   string `json:"source"`
		Type     string `json:"type"`
		CvssData struct {
			Version               string  `json:"version"`
			VectorString          string  `json:"vectorString"`
			AttackVector          string  `json:"attackVector"`
			AttackComplexity      string  `json:"attackComplexity"`
			PrivilegesRequired    string  `json:"privilegesRequired"`
			UserInteraction       string  `json:"userInteraction"`
			Scope                 string  `json:"scope"`
			ConfidentialityImpact string  `json:"confidentialityImpact"`
			IntegrityImpact       string  `json:"integrityImpact"`
			AvailabilityImpact    string  `json:"availabilityImpact"`
			BaseScore             float64 `json:"baseScore"`
			BaseSeverity          string  `json:"baseSeverity"`
		} `json:"cvssData"`
		ExploitabilityScore float64 `json:"exploitabilityScore"`
		ImpactScore         float64 `json:"impactScore"`
	} `json:"cvssMetricV30,omitempty"`
	CvssMetricV31 []struct {
		Source   string `json:"source"`
		Type     string `json:"type"`
		CvssData struct {
			Version               string  `json:"version"`
			VectorString          string  `json:"vectorString"`
			AttackVector          string  `json:"attackVector"`
			AttackComplexity      string  `json:"attackComplexity"`
			PrivilegesRequired    string  `json:"privilegesRequired"`
			UserInteraction       string  `json:"userInteraction"`
			Scope                 string  `json:"scope"`
			ConfidentialityImpact string  `json:"confidentialityImpact"`
			IntegrityImpact       string  `json:"integrityImpact"`
			AvailabilityImpact    string  `json:"availabilityImpact"`
			BaseScore             float64 `json:"baseScore"`
			BaseSeverity          string  `json:"baseSeverity"`
		} `json:"cvssData"`
		ExploitabilityScore float64 `json:"exploitabilityScore"`
		ImpactScore         float64 `json:"impactScore"`
	} `json:"cvssMetricV31,omitempty"`
}

type CpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
}

func vulnerabilityToCve(v Vulnerability, _ int) Cve {
	return v.Cve
}
