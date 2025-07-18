package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	mspID        = "Org1MSP"
	cryptoPath   = "../../test-network/organizations/peerOrganizations/org1.example.com"
	certPath     = cryptoPath + "/users/User1@org1.example.com/msp/signcerts"
	keyPath      = cryptoPath + "/users/User1@org1.example.com/msp/keystore"
	tlsCertPath  = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint = "localhost:7051"
	gatewayPeer  = "peer0.org1.example.com"

	defaultChaincodeName = "basic"
	defaultChannelName   = "mychannel"

	// Define the port for the Go middleware
	middlewarePort = "8081" // Set your Go middleware to listen on this port
)

var (
	fabricGateway  *client.Gateway
	fabricContract *client.Contract
)

type ErrorResponse struct {
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

type InitLedgerResponse struct {
	Message string `json:"message"`
}

type GetAllAssetsResponse struct {
	Assets []Asset `json:"assets"`
}

type CreateAssetRequest struct {
	ID             string `json:"id"`
	Color          string `json:"color"`
	Size           int    `json:"size"`
	Owner          string `json:"owner"`
	AppraisedValue int    `json:"appraisedValue"`
}

type Asset struct {
	ID             string `json:"ID"`
	Color          string `json:"Color"`
	Size           int    `json:"Size"`
	Owner          string `json:"Owner"`
	AppraisedValue int    `json:"AppraisedValue"`
}

type TransferAssetRequest struct {
	ID       string `json:"id"`
	NewOwner string `json:"newOwner"`
}

type TransferAssetResponse struct {
	Message       string `json:"message"`
	TransactionID string `json:"transactionId"`
}

func main() {
	err := initFabricGateway()
	if err != nil {
		log.Fatalf("Failed to initialize Fabric Gateway: %v", err)
	}
	defer fabricGateway.Close()

	// Wrap your handlers with the enableCORS middleware
	http.HandleFunc("/api/init-ledger", enableCORS(initLedgerHandler))
	http.HandleFunc("/api/assets", enableCORS(assetsHandler))
	http.HandleFunc("/api/assets/", enableCORS(assetByIdHandler))
	http.HandleFunc("/api/assets/transfer", enableCORS(transferAssetHandler))
	http.HandleFunc("/api/error-test", enableCORS(errorTestHandler))

	// Get port from environment variable or use the defined constant
	port := os.Getenv("PORT")
	if port == "" {
		port = middlewarePort // Use the constant defined for the Go middleware
	}

	log.Printf("Starting Go middleware server on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// enableCORS is a middleware function that adds CORS headers to responses.
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set the Access-Control-Allow-Origin header to allow requests from any origin.
		// For production, you should replace "*" with the specific origin(s) of your web application
		// (e.g., "http://localhost:8000").
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		// Handle preflight requests (OPTIONS method)
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler in the chain
		next(w, r)
	}
}

func initFabricGateway() error {
	log.Println("Initializing Fabric Gateway connection...")
	clientConnection := newGrpcConnection()

	id := newIdentity()
	sign := newSign()

	var err error
	fabricGateway, err = client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(clientConnection),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to Fabric Gateway: %w", err)
	}

	chaincodeName := os.Getenv("CHAINCODE_NAME")
	if chaincodeName == "" {
		chaincodeName = defaultChaincodeName
	}
	channelName := os.Getenv("CHANNEL_NAME")
	if channelName == "" {
		channelName = defaultChannelName
	}

	network := fabricGateway.GetNetwork(channelName)
	fabricContract = network.GetContract(chaincodeName)

	log.Printf("Fabric Gateway initialized for channel '%s', chaincode '%s'\n", channelName, chaincodeName)
	return nil
}

func newGrpcConnection() *grpc.ClientConn {
	certificatePEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		log.Fatalf("Failed to read TLS certificate file: %v", err)
	}

	certificate, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		log.Fatalf("Failed to parse TLS certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	connection, err := grpc.NewClient(peerEndpoint, grpc.WithTransportCredentials(transportCredentials), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to create gRPC connection: %v", err)
	}

	return connection
}

func newIdentity() *identity.X509Identity {
	certificatePEM, err := readFirstFile(certPath)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	certificate, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		log.Fatalf("Failed to parse identity certificate: %v", err)
	}

	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		log.Fatalf("Failed to create X.509 identity: %v", err)
	}

	return id
}

func newSign() identity.Sign {
	privateKeyPEM, err := readFirstFile(keyPath)
	if err != nil {
		log.Fatalf("Failed to read private key file: %v", err)
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		log.Fatalf("Failed to create private key sign function: %v", err)
	}

	return sign
}

func readFirstFile(dirPath string) ([]byte, error) {
	dir, err := os.Open(dirPath)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	fileNames, err := dir.Readdirnames(1)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(path.Join(dirPath, fileNames[0]))
}

func writeJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	// CORS headers are now set by the enableCORS middleware
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		// Don't call http.Error here, as headers might already be sent
		// Instead, just log and possibly write a simple message if possible.
		fmt.Fprintf(w, "Internal Server Error during JSON encoding")
	}
}

func handleFabricError(w http.ResponseWriter, err error, action string) {
	log.Printf("Fabric error during %s: %v", action, err)

	message := fmt.Sprintf("Failed to %s on blockchain: %v", action, err)
	details := ""
	httpStatus := http.StatusInternalServerError

	var endorseErr *client.EndorseError
	var submitErr *client.SubmitError
	var commitStatusErr *client.CommitStatusError
	var commitErr *client.CommitError

	if errors.As(err, &endorseErr) {
		message = fmt.Sprintf("Endorsement failed for transaction %s: %s", endorseErr.TransactionID, endorseErr)
		httpStatus = http.StatusBadRequest
	} else if errors.As(err, &submitErr) {
		message = fmt.Sprintf("Transaction submission failed for %s: %s", submitErr.TransactionID, submitErr)
		httpStatus = http.StatusInternalServerError
	} else if errors.As(err, &commitStatusErr) {
		if errors.Is(err, context.DeadlineExceeded) {
			message = fmt.Sprintf("Timeout waiting for transaction %s commit status: %s", commitStatusErr.TransactionID, commitStatusErr)
			httpStatus = http.StatusAccepted
		} else {
			message = fmt.Sprintf("Error obtaining commit status for transaction %s: %s", commitStatusErr.TransactionID, commitStatusErr)
			httpStatus = http.StatusInternalServerError
		}
	} else if errors.As(err, &commitErr) {
		message = fmt.Sprintf("Transaction %s failed to commit with status %d: %s", commitErr.TransactionID, int32(commitErr.Code), err)
		httpStatus = http.StatusInternalServerError
	}

	statusErr, ok := status.FromError(err)
	if ok {
		for _, detail := range statusErr.Details() {
			if errDetail, isGatewayError := detail.(*gateway.ErrorDetail); isGatewayError {
				details += fmt.Sprintf("Peer: %s, MSP: %s, Msg: %s; ", errDetail.Address, errDetail.MspId, errDetail.Message)
			}
		}
		if details == "" && statusErr.Message() != "" {
			details = statusErr.Message()
		}
	}

	writeJSONResponse(w, httpStatus, ErrorResponse{
		Message: message,
		Details: details,
	})
}

func initLedgerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Println("Received POST /api/init-ledger request")

	_, err := fabricContract.SubmitTransaction("InitLedger")
	if err != nil {
		handleFabricError(w, err, "initialize ledger")
		return
	}

	writeJSONResponse(w, http.StatusOK, InitLedgerResponse{Message: "Ledger initialized successfully"})
	log.Println("Responded to POST /api/init-ledger")
}

func assetsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getAllAssetsHandler(w, r)
	case http.MethodPost:
		createAssetHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getAllAssetsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received GET /api/assets request")

	evaluateResult, err := fabricContract.EvaluateTransaction("GetAllAssets")
	if err != nil {
		handleFabricError(w, err, "get all assets")
		return
	}

	var assets []Asset
	if err := json.Unmarshal(evaluateResult, &assets); err != nil {
		log.Printf("Error unmarshalling GetAllAssets result: %v", err)
		http.Error(w, "Internal Server Error: Failed to parse blockchain data", http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusOK, GetAllAssetsResponse{Assets: assets})
	log.Println("Responded to GET /api/assets")
}

func createAssetHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received POST /api/assets request")
	var req CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ID == "" || req.Color == "" || req.Size == 0 || req.Owner == "" || req.AppraisedValue == 0 { // Check int default
		http.Error(w, "Missing required asset fields or invalid AppraisedValue", http.StatusBadRequest)
		return
	}

	_, err := fabricContract.SubmitTransaction(
		"CreateAsset",
		req.ID,
		req.Color,
		fmt.Sprintf("%d", req.Size), // Convert int to string for chaincode argument
		req.Owner,
		fmt.Sprintf("%d", req.AppraisedValue), // Convert int to string for chaincode argument
	)
	if err != nil {
		handleFabricError(w, err, fmt.Sprintf("create asset %s", req.ID))
		return
	}

	writeJSONResponse(w, http.StatusCreated, map[string]string{"message": fmt.Sprintf("Asset %s created successfully", req.ID)})
	log.Printf("Responded to POST /api/assets for asset %s\n", req.ID)
}

func assetByIdHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Asset ID is required in the URL path", http.StatusBadRequest)
		return
	}
	assetID := parts[3]

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Printf("Received GET /api/assets/%s request\n", assetID)

	evaluateResult, err := fabricContract.EvaluateTransaction("ReadAsset", assetID)
	if err != nil {
		handleFabricError(w, err, fmt.Sprintf("read asset %s", assetID))
		return
	}

	var asset Asset
	if err := json.Unmarshal(evaluateResult, &asset); err != nil {
		log.Printf("Error unmarshalling ReadAsset result for %s: %v", assetID, err)
		http.Error(w, "Internal Server Error: Failed to parse blockchain data", http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusOK, asset)
	log.Printf("Responded to GET /api/assets/%s\n", assetID)
}

func transferAssetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Println("Received POST /api/assets/transfer request")

	var req TransferAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ID == "" || req.NewOwner == "" {
		http.Error(w, "Missing required fields: id, newOwner", http.StatusBadRequest)
		return
	}

	_, commit, err := fabricContract.SubmitAsync("TransferAsset", client.WithArguments(req.ID, req.NewOwner))
	if err != nil {
		handleFabricError(w, err, fmt.Sprintf("transfer asset %s asynchronously", req.ID))
		return
	}

	txID := commit.TransactionID()

	response := TransferAssetResponse{
		Message:       fmt.Sprintf("Transaction for transfer of asset %s to %s submitted successfully.", req.ID, req.NewOwner),
		TransactionID: txID,
	}
	writeJSONResponse(w, http.StatusAccepted, response)
	log.Printf("Responded to POST /api/assets/transfer for asset %s (async submission), TxID: %s\n", req.ID, txID)

	go func(txID string, commit *client.Commit) {
		log.Printf("Waiting for commit status for transaction %s...", txID)
		commitStatus, err := commit.Status()
		if err != nil {
			log.Printf("Error getting commit status for transaction %s: %v", txID, err)
			return
		}

		if !commitStatus.Successful {
			log.Printf("Transaction %s failed to commit with status code: %d", commitStatus.TransactionID, int32(commitStatus.Code))
		} else {
			log.Printf("Transaction %s committed successfully (async)", commitStatus.TransactionID)
		}
	}(txID, commit)
}

func errorTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Println("Received POST /api/error-test request (simulating an invalid transaction)")

	_, err := fabricContract.SubmitTransaction("UpdateAsset", "asset70", "blue", "5", "Tomoko", "300")
	if err == nil {
		log.Println("ERROR: Expected an error but none occurred for error-test")
		http.Error(w, "Internal Server Error: Expected error not returned", http.StatusInternalServerError)
		return
	}

	handleFabricError(w, err, "test error handling with UpdateAsset")
	log.Println("Responded to POST /api/error-test")
}
