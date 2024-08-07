package chaincode

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing an Incident
type SmartContract struct {
	contractapi.Contract
}

// State that represents an incident with all its attributes
// includes JSON tags for serialization
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

// struct used for storing the history of a transaction by using the built-in functionality of HF
type HistoryQueryResult struct {
	TxId      string    `json:"txId"`
	Value     string    `json:"value"`
	Timestamp time.Time `json:"timestamp"`
	IsDelete  bool      `json:"isDelete"`
}

func (i Incident) MarshalJSON() ([]byte, error) {
	type Alias Incident
	return json.Marshal(&struct {
		CreatedTime  string `json:"CreatedTime"`
		UpdatedTime  string `json:"UpdatedTime,omitempty"` // Ensure UpdatedTime is handled appropriately
		DetectedTime string `json:"DetectedTime"`
		*Alias
	}{
		CreatedTime:  i.CreatedTime.Format(time.RFC3339),
		UpdatedTime:  i.UpdatedTime.Format(time.RFC3339),
		DetectedTime: i.DetectedTime.Format(time.RFC3339),
		Alias:        (*Alias)(&i),
	})
}

func (i *Incident) UnmarshalJSON(data []byte) error {
	type Alias Incident
	aux := &struct {
		CreatedTime  string `json:"CreatedTime"`
		UpdatedTime  string `json:"UpdatedTime"`
		DetectedTime string `json:"DetectedTime"`
		*Alias
	}{
		Alias: (*Alias)(i),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	var err error
	i.CreatedTime, err = time.Parse(time.RFC3339, aux.CreatedTime)
	if err != nil {
		return err
	}
	if aux.UpdatedTime != "" {
		i.UpdatedTime, err = time.Parse(time.RFC3339, aux.UpdatedTime)
		if err != nil {
			return err
		}
	}
	i.DetectedTime, err = time.Parse(time.RFC3339, aux.DetectedTime)
	if err != nil {
		return err
	}
	return nil
}

// InitLedger adds a base set of incidents to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	// Example incidents
	incidents := []Incident{
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
		{
			AffectedSystems: []string{"ITSystemPeer2", "ITTeamPeer"},
			Description:     "ITSystemPeer2 experienced a hardware failure, leading to an unexpected outage and disruption in processing transactions and endorsing proposals.",
			IncidentId:      "INC1002",
			Issuer:          "ITTeamPeer",
			SeverityLevel:   "High",
			Status:          "In Review",
			CreatedTime:     time.Now(),
			UpdatedTime:     time.Time{},
			DetectedTime:    time.Now().Add(-2 * time.Hour),
			Type:            "Technical",
			Impact:          "Not specified",
			RecoverySteps:   "Not specified",
			Resolution:      "Not specified",
		},
		{
			AffectedSystems: []string{"ITTeamPeer", "ITSystemPeer1"},
			Description:     "A power failure at the data center hosting ManualSubmissionPeer and ITSystemPeer1 caused a temporary loss of service, impacting transaction submission and endorsement capabilities.",
			IncidentId:      "INC1003",
			Issuer:          "ManualSubmissionPeer",
			SeverityLevel:   "High",
			Status:          "Open",
			CreatedTime:     time.Now(),
			UpdatedTime:     time.Time{},
			DetectedTime:    time.Now().Add(-30 * time.Minute),
			Type:            "Physical",
			Impact:          "Not specified",
			RecoverySteps:   "Not specified",
			Resolution:      "Not specified",
		},
		{
			AffectedSystems: []string{"ITTeamPeer"},
			Description:     "A configuration error on ITTeamPeer led to inadvertent exposure of sensitive transaction data during the endorsement process, raising concerns about data privacy and confidentiality.",
			IncidentId:      "INC1004",
			Issuer:          "ITSystemPeer2",
			SeverityLevel:   "Medium",
			Status:          "In Review",
			CreatedTime:     time.Now(),
			UpdatedTime:     time.Time{}, // Zero value indicates no updates yet.
			DetectedTime:    time.Now().Add(-15 * time.Minute),
			Type:            "Privacy",
			Impact:          "Not specified",
			RecoverySteps:   "Not specified",
			Resolution:      "Not specified",
		},
		{
			AffectedSystems: []string{"ITSystemPeer1", "ITTeamPeer"},
			Description:     "An unauthorized access attempt was detected on ITSystemPeer1, potentially aiming to compromise the peer and inject fraudulent transactions into the network.",
			IncidentId:      "INC1005",
			Issuer:          "ITSystemPeer2",
			SeverityLevel:   "Critical",
			Status:          "Open",
			CreatedTime:     time.Now(),
			UpdatedTime:     time.Time{},                // Zero value as no updates yet
			DetectedTime:    time.Now().Add(-time.Hour), // Assume detected an hour before creationAC
			Type:            "Security",
			Impact:          "Not specified",
			RecoverySteps:   "Not specified",
			Resolution:      "Not specified",
		},
		{
			AffectedSystems: []string{"ITSystemPeer2", "ITTeamPeer"},
			Description:     "ITSystemPeer2 experienced a hardware failure, leading to an unexpected outage and disruption in processing transactions and endorsing proposals.",
			IncidentId:      "INC1006",
			Issuer:          "ITTeamPeer",
			SeverityLevel:   "High",
			Status:          "In Review",
			CreatedTime:     time.Now(),
			UpdatedTime:     time.Time{},
			DetectedTime:    time.Now().Add(-2 * time.Hour), // Assume detected two hours before creation
			Type:            "Technical",
			Impact:          "Not specified",
			RecoverySteps:   "Not specified",
			Resolution:      "Not specified",
		},
	}

	for _, incident := range incidents {
		incidentJSON, err := json.Marshal(incident)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(incident.IncidentId, incidentJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
	}

	return nil
}

// ValidSeverityLevels defines the allowed severity levels for incidents
var ValidSeverityLevels = []string{"Not specified", "Critical", "High", "Medium", "Minor", "Informational"}

// ValidIncidentTypes defines the allowed types for incidents
var ValidIncidentTypes = []string{"Security", "Technical", "Physical", "Privacy", "Compliance"}

// Contains checks if a string is in a slice of strings
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

const incidentCounterKey = "incidentCounter"

// CreateIncident issues a new incident to the world state with given details.
func (s *SmartContract) CreateIncident(ctx contractapi.TransactionContextInterface, affectedSystems []string, description string, issuer string, severityLevel string, incidentType string) error {
	// Validate SeverityLevel
	if !Contains(ValidSeverityLevels, severityLevel) {
		return fmt.Errorf("invalid severity level: %v. Must be one of %v", severityLevel, ValidSeverityLevels)
	}

	// Validate Incident Type
	if !Contains(ValidIncidentTypes, incidentType) {
		return fmt.Errorf("invalid incident type: %v. Must be one of %v", incidentType, ValidIncidentTypes)
	}

	// Retrieve the current incident counter from the world state
	counterBytes, err := ctx.GetStub().GetState(incidentCounterKey)
	if err != nil {
		return fmt.Errorf("failed to get the incident counter: %v", err)
	}

	var counter int
	if counterBytes == nil {
		// Initialize counter if it does not exist
		counter = 0
	} else {
		// Unmarshal the counter value
		err = json.Unmarshal(counterBytes, &counter)
		if err != nil {
			return fmt.Errorf("failed to unmarshal incident counter: %v", err)
		}
	}

	// Increment the counter to use as the next incident number
	counter++
	incidentId := fmt.Sprintf("INC%06d", counter)

	now := time.Now() // Current time for CreatedTime
	incident := Incident{
		AffectedSystems: affectedSystems,
		Description:     description,
		IncidentId:      incidentId,
		Issuer:          issuer,
		SeverityLevel:   severityLevel,
		Status:          "Open",
		CreatedTime:     now,
		UpdatedTime:     time.Time{},
		DetectedTime:    now,
		Type:            incidentType,
		Impact:          "Not specified",
		RecoverySteps:   "Not specified",
		Resolution:      "Not specified",
	}

	incidentJSON, err := json.Marshal(incident)
	if err != nil {
		return err
	}

	// Update the world state with the new incident
	err = ctx.GetStub().PutState(incidentId, incidentJSON)
	if err != nil {
		return fmt.Errorf("failed to create the new incident in the world state: %v", err)
	}

	// Update the counter in the world state
	updatedCounterBytes, err := json.Marshal(counter)
	if err != nil {
		return fmt.Errorf("failed to marshal the updated incident counter: %v", err)
	}
	err = ctx.GetStub().PutState(incidentCounterKey, updatedCounterBytes)
	if err != nil {
		return fmt.Errorf("failed to update the incident counter in the world state: %v", err)
	}
	ctx.GetStub().SetEvent("IncidentCreated", []byte(fmt.Sprintf("Incident ID: %s, Description: %s", incidentId, description)))
	return nil
}

// ReviewIncident updates an existing incident's status to "In Review".
func (s *SmartContract) ReviewIncident(ctx contractapi.TransactionContextInterface, incidentId string) error {
	incidentJSON, err := ctx.GetStub().GetState(incidentId)

	//Error handling in the case the incident does not exist
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if incidentJSON == nil {
		return fmt.Errorf("the incident %s does not exist", incidentId)
	}

	var incident Incident
	err = json.Unmarshal(incidentJSON, &incident)
	if err != nil {
		return err
	}

	// Update the status to "In Review"
	incident.Status = "In Review"
	incident.UpdatedTime = time.Now() // Set UpdatedTime to current time

	//Marshal back the result with the modified properties
	updatedIncidentJSON, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	ctx.GetStub().SetEvent("IncidentReviewed", []byte(fmt.Sprintf("Incident ID: %s", incidentId)))
	return ctx.GetStub().PutState(incidentId, updatedIncidentJSON)
}

// ResolveIncident finalizes the incident by setting its status to "Resolved" and adds resolution details, impact assessment, and recovery steps.
func (s *SmartContract) ResolveIncident(ctx contractapi.TransactionContextInterface, incidentId string, resolutionDescription, impact, recoverySteps string) error {
	incidentJSON, err := ctx.GetStub().GetState(incidentId)

	//Error handling in the case the incident does not exist
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if incidentJSON == nil {
		return fmt.Errorf("the incident %s does not exist", incidentId)
	}

	var incident Incident
	err = json.Unmarshal(incidentJSON, &incident)
	if err != nil {
		return err
	}

	// Update the incident with resolution details
	incident.Status = "Resolved"
	incident.Description += "\nResolution: " + resolutionDescription
	incident.Impact = impact
	incident.Resolution = resolutionDescription
	incident.RecoverySteps = recoverySteps
	incident.UpdatedTime = time.Now()

	//Marshal back the transaction with the modified properties
	updatedIncidentJSON, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	ctx.GetStub().SetEvent("IncidentResolved", []byte(fmt.Sprintf("Incident ID: %s, Resolution: %s", incidentId, incident.Resolution)))
	return ctx.GetStub().PutState(incidentId, updatedIncidentJSON)
}

// DeleteIncident deletes a given incident from the world state.
func (s *SmartContract) DeleteIncident(ctx contractapi.TransactionContextInterface, incidentId string) error {
	exists, err := s.IncidentExists(ctx, incidentId)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the incident %s does not exist", incidentId)
	}
	err = ctx.GetStub().SetEvent("IncidentDeleted", []byte(fmt.Sprintf("Incident ID: %s deleted", incidentId)))
	if err != nil {
		return fmt.Errorf("failed to emit incident deleted event: %v", err)
	}
	//Calls DelState() method for deleting an incident
	return ctx.GetStub().DelState(incidentId)
}

// IncidentExists returns true when incident with given ID exists in world state
func (s *SmartContract) IncidentExists(ctx contractapi.TransactionContextInterface, incidentId string) (bool, error) {
	incidentJSON, err := ctx.GetStub().GetState(incidentId)

	//Error handling in the case incident is not found
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return incidentJSON != nil, nil
}

// GetAllIncidents returns all incidents found in world state
func (s *SmartContract) GetAllIncidents(ctx contractapi.TransactionContextInterface) ([]*Incident, error) {
	// Open-ended query of all incidents in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var incidents []*Incident

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("error retrieving next item: %v", err)
		}

		var incident Incident
		err = json.Unmarshal(queryResponse.Value, &incident)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling incident from key %s: %v", queryResponse.Key, err)
		}
		incidents = append(incidents, &incident)

		// Convert the incident to pretty JSON for better readability
		prettyJSON, err := json.MarshalIndent(incident, "", "    ") // Indent with 4 spaces
		if err != nil {
			fmt.Println("Error formatting JSON:", err)
		} else {
			fmt.Println(string(prettyJSON))
		}
	}
	return incidents, nil
}

// GetHistoryForIncident retrieves the history of changes made to an incident.
func (s *SmartContract) GetHistoryForIncident(ctx contractapi.TransactionContextInterface, incidentId string) ([]HistoryQueryResult, error) {
	resultsIterator, err := ctx.GetStub().GetHistoryForKey(incidentId)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var records []HistoryQueryResult
	fmt.Println("TxID\tTimestamp\tIsDelete\tIncident Details")
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		record := HistoryQueryResult{
			TxId:      response.TxId,
			Value:     string(response.Value),
			Timestamp: time.Unix(response.Timestamp.Seconds, int64(response.Timestamp.Nanos)),
			IsDelete:  response.IsDelete,
		}
		var incident Incident
		if len(response.Value) > 0 {
			err = json.Unmarshal(response.Value, &incident)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling incident: %v", err)
			}
			record.Value = fmt.Sprintf("%s | %s | %s | %s", incident.Description, incident.SeverityLevel, incident.Status, incident.Type)
		}
		records = append(records, record)

		deleteMarker := ""
		if record.IsDelete {
			deleteMarker = "Deleted"
		}

		fmt.Printf("%s\t%s\t%s\t%s\n", record.TxId, record.Timestamp.Format(time.RFC3339), deleteMarker, record.Value)
	}

	return records, nil
}

// GetAllIncidentsByAffectedSystem returns all incidents with a specific affected system
func (s *SmartContract) GetAllIncidentsByAffectedSystem(ctx contractapi.TransactionContextInterface, affectedSystem string) ([]*Incident, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var incidents []*Incident

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var incident Incident
		err = json.Unmarshal(queryResponse.Value, &incident)
		if err != nil {
			return nil, err
		}
		// Check if the affected system is part of this incident
		for _, system := range incident.AffectedSystems {
			if system == affectedSystem {
				incidents = append(incidents, &incident)
				break
			}
		}
	}

	return incidents, nil
}

// GetAllIncidentsByIssuer returns all incidents with a specific issuer
func (s *SmartContract) GetAllIncidentsByIssuer(ctx contractapi.TransactionContextInterface, issuer string) ([]*Incident, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var incidents []*Incident

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var incident Incident
		err = json.Unmarshal(queryResponse.Value, &incident)
		if err != nil {
			return nil, err
		}
		// Check if the issuer matches
		if incident.Issuer == issuer {
			incidents = append(incidents, &incident)
		}
	}

	return incidents, nil
}

// GetAllIncidentsByType returns all incidents with a specific type
func (s *SmartContract) GetAllIncidentsByType(ctx contractapi.TransactionContextInterface, incidentType string) ([]*Incident, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var incidents []*Incident

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var incident Incident
		err = json.Unmarshal(queryResponse.Value, &incident)
		if err != nil {
			return nil, err
		}
		// Check if the type matches
		if incident.Type == incidentType {
			incidents = append(incidents, &incident)
		}
	}

	return incidents, nil
}

// GetAllIncidentsBySeverity returns all incidents with a specific severity level
func (s *SmartContract) GetAllIncidentsBySeverity(ctx contractapi.TransactionContextInterface, severityLevel string) ([]*Incident, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var incidents []*Incident

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var incident Incident
		err = json.Unmarshal(queryResponse.Value, &incident)
		if err != nil {
			return nil, err
		}
		// Check if the severity level matches with the one send as parameter
		if incident.SeverityLevel == severityLevel {
			incidents = append(incidents, &incident)
		}
	}

	return incidents, nil
}

// functions for chaincode 2 - retrieving information
// utility function for executing CouchDB query strng and parse the results into a structured format
func queryIncidents(ctx contractapi.TransactionContextInterface, queryString string) ([]Incident, error) {
	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var incidents []Incident
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var incident Incident
		if err := json.Unmarshal(response.Value, &incident); err != nil {
			return nil, err
		}
		incidents = append(incidents, incident)
	}
	return incidents, nil
}

// GetCriticalIncidentsUpdatedRecently retrieves incidents with "Critical" severity that were updated in the last 24 hours.
func (s *SmartContract) GetCriticalIncidentsUpdatedRecently(ctx contractapi.TransactionContextInterface) ([]Incident, error) {
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)
	queryString := fmt.Sprintf(`{
        "selector": {
            "severityLevel": "Critical",
            "updatedTime": {
                "$gte": "%s",
                "$lte": "%s"
            }
        }
    }`, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))

	return queryIncidents(ctx, queryString)
}

// GetIncidentsByTypeAndSeverity retrieves incidents of a specific type and severity in the last month.
func (s *SmartContract) GetIncidentsByTypeAndSeverity(ctx contractapi.TransactionContextInterface, incidentType, severity string) ([]Incident, error) {
	currentTime := time.Now()
	lastMonthTime := currentTime.AddDate(0, -1, 0)
	queryString := fmt.Sprintf(`{
        "selector": {
            "type": "%s",
            "severityLevel": "%s",
            "detectedTime": {
                "$gte": "%s"
            }
        }
    }`, incidentType, severity, lastMonthTime.Format(time.RFC3339))

	return queryIncidents(ctx, queryString)
}
func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})

	if err != nil {
		fmt.Printf("Error create incident chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting incident chaincode: %s", err.Error())
	}
}
