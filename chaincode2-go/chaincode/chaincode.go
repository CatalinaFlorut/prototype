package chaincode

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Incident represents the structure of an incident and contains several fields of the incident
type Incident struct {
	AffectedSystems []string  `json:"AffectedSystems"`
	Description     string    `json:"Description"`
	IncidentId      string    `json:"IncidentId"`
	Issuer          string    `json:"Issuer"`
	SeverityLevel   string    `json:"SeverityLevel"`
	Status          string    `json:"Status"`
	CreatedTime     time.Time `json:"CreatedTime"`
	UpdatedTime     time.Time `json:"UpdatedTime,omitempty"`
	DetectedTime    time.Time `json:"DetectedTime"`
	Type            string    `json:"Type"`
	Impact          string    `json:"Impact,omitempty"`
	RecoverySteps   string    `json:"RecoverySteps,omitempty"`
	Resolution      string    `json:"Resolution,omitempty"`
}

// Report contains details of incidents and metadata for a report
type Report struct {
	ReportId   string     `json:"reportId"`
	CreatedAt  time.Time  `json:"createdAt"`
	ReportType string     `json:"reportType"`
	Incidents  []Incident `json:"incidents"`
	Message    string     `json:"message"` // Descriptive message for the report
}

type SmartContract struct {
	contractapi.Contract
}

// Init initializes the chaincode with sample data
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	// Sample data
	exampleReports := []Report{
		{
			ReportId:   "RPT0001",
			CreatedAt:  time.Now(),
			ReportType: "Initial Incident Report",
			Incidents: []Incident{
				{
					AffectedSystems: []string{"ITSystemPeer1", "ITTeamPeer"},
					Description:     "An unauthorized access attempt was detected on ITSystemPeer1, potentially aiming to compromise the peer and inject fraudulent transactions into the network.",
					IncidentId:      "INC1001",
					Issuer:          "ITSystemPeer2",
					SeverityLevel:   "Critical",
					Status:          "Open",
					CreatedTime:     time.Now(),
					UpdatedTime:     time.Time{}, // Zero value as no updates yet
					DetectedTime:    time.Now().Add(-time.Hour),
					Type:            "Security",
					Impact:          "Not specified",
					RecoverySteps:   "Not specified",
					Resolution:      "Not specified",
				},
			},
			Message: "Initial test report containing one incident.",
		},
	}

	// Store each report in the ledger
	for _, report := range exampleReports {
		reportJSON, err := json.Marshal(report)
		if err != nil {
			return fmt.Errorf("failed to marshal report %s: %v", report.ReportId, err)
		}

		err = ctx.GetStub().PutState(report.ReportId, reportJSON)
		if err != nil {
			return fmt.Errorf("failed to put report %s to state: %v", report.ReportId, err)
		}
	}

	fmt.Println("Initialized the ledger with sample reports")
	return nil
}

// QueryChaincode1 fetches incident data from Chaincode 1 using chaincode-to-chaincode invocation
func (s *SmartContract) QueryChaincode1(ctx contractapi.TransactionContextInterface, chaincodeName, functionName string, args []string) ([]Incident, error) {
	var ccArgs [][]byte
	ccArgs = append(ccArgs, []byte(functionName))
	for _, arg := range args {
		ccArgs = append(ccArgs, []byte(arg))
	}
	// invoke chainocde 1 for retrieving the incident using InvokeChaincode method
	response := ctx.GetStub().InvokeChaincode(chaincodeName, ccArgs, "channel1")
	if response.Status != 200 {
		return nil, fmt.Errorf("error invoking chaincode %s, function %s: %s", chaincodeName, functionName, response.Message)
	}

	//unmarshal response form chaincode 1
	var incidents []Incident
	if err := json.Unmarshal(response.Payload, &incidents); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response from Chaincode 1 (queryChaincode)): %v", err)
	}

	return incidents, nil
}

// CreateCriticalIncidentsReport generates a report for critical incidents updated in the last 24 hours
func (s *SmartContract) CreateCriticalIncidentsReport(ctx contractapi.TransactionContextInterface) (string, error) {
	incidents, err := s.QueryChaincode1(ctx, "basic", "GetCriticalIncidentsUpdatedRecently", []string{})
	if err != nil {
		return "", err
	}
	//creates the report using a standard message and the queried incidents
	reportMessage := "This report summarizes critical incidents updated within the last 24 hours. The details contain the name, description and have the severitz Criticical."
	//set the fields of the report with unmarshal data from chaincode 1
	report := Report{
		ReportId:   fmt.Sprintf("REPORT_%d", time.Now().UnixNano()),
		CreatedAt:  time.Now(),
		ReportType: "CriticalIncidents",
		Incidents:  incidents,
		Message:    reportMessage,
	}

	//error handling
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("error marshalling report(CreateCriticalIncidentReport): %s", err)
	}

	return string(reportJSON), nil
}

// CreateSecurityIncidentsReport generates a report for all security incidents from the last month
func (s *SmartContract) CreateSecurityIncidentsReport(ctx contractapi.TransactionContextInterface) (string, error) {
	incidents, err := s.QueryChaincode1(ctx, "basic", "GetIncidentsByTypeAndSeverity", []string{"Security", "All"})
	if err != nil {
		return "", err
	}

	//creates the report with a standard message and the queried incidents
	reportMessage := "This report details all security-related incidents identified in the last month, highlighting potential vulnerabilities and threats."
	report := Report{
		ReportId:   fmt.Sprintf("REPORT_%d", time.Now().UnixNano()),
		CreatedAt:  time.Now(),
		ReportType: "SecurityIncidents",
		Incidents:  incidents,
		Message:    reportMessage,
	}

	reportJSON, err := json.Marshal(report)

	// error handling
	if err != nil {
		return "", fmt.Errorf("error marshalling report(CreateSecurityIncdientReport): %s", err)
	}

	return string(reportJSON), nil
}

// GetAllReports returns all reports found in the ledger in a nicely formatted way
func (s *SmartContract) GetAllReports(ctx contractapi.TransactionContextInterface) (string, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return "", err
	}
	defer resultsIterator.Close()

	var reports []*Report
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return "", fmt.Errorf("failed to iterate through reports: %v", err)
		}

		var report Report
		err = json.Unmarshal(queryResponse.Value, &report)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal report: %v", err)
		}
		reports = append(reports, &report)
	}

	// Marshal the reports into JSON with indentation for pretty output
	prettyJSON, err := json.MarshalIndent(reports, "", "    ") // Indent with 4 spaces for pretty JSON
	if err != nil {
		return "", fmt.Errorf("error marshalling reports: %s", err)
	}

	return string(prettyJSON), nil
}

// Main function starts up the chaincode in the container during instantiation
func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))

	//error handling
	if err != nil {
		fmt.Printf("Error creating incident report chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting incident report chaincode: %s", err.Error())
	}
}
