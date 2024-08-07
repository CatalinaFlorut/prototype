Function TestCreateIncident(t)
    // Setup the mock environment
    chaincodeStub = CreateMockChaincodeStub()
    transactionContext = CreateMockTransactionContext()
    transactionContext.GetStubReturns(chaincodeStub)

    incidentManagement = new SmartContract()

    // Test case 1: Successfully creating an incident
    error = incidentManagement.CreateIncident(transactionContext, ["ITSystemPeer1"], "Unauthorized access detected", "ITTeamPeer", "High", "Security")
    AssertNoError(error, "Creating an incident should not result in an error")

    // Test case 2: Simulate a failure in retrieving state from the chaincode stub
    chaincodeStub.GetStateReturns(None, "unable to retrieve state")
    error = incidentManagement.CreateIncident(transactionContext, ["ITSystemPeer2"], "Hardware failure", "ITTeamPeer", "Medium", "Technical")
    AssertErrorWithMessage(error, "failed to get the incident counter: unable to retrieve state", "Expected an error when unable to retrieve state")

    // Reset the stub to simulate a successful state retrieval for subsequent tests
    chaincodeStub.GetStateReturns("1", None)
