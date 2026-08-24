// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

type Request struct {
	Version int    `json:"version"`
	Op      string `json:"op"`
	Nonce   string `json:"nonce"`
}

type Response struct {
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	Token   string `json:"token,omitempty"`
	Error   string `json:"error,omitempty"`
	Nonce   string `json:"nonce"`
	MAC     string `json:"mac"`
}

func NewRequest(operation string) (Request, error) {
	if !validOperation(operation) {
		return Request{}, fmt.Errorf("%w: unsupported operation", ErrProtocol)
	}
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return Request{}, fmt.Errorf("generate broker nonce: %w", err)
	}
	return Request{
		Version: ProtocolVersion,
		Op:      operation,
		Nonce:   hex.EncodeToString(nonce[:]),
	}, nil
}

func DecodeRequest(message []byte) (Request, error) {
	if len(message) == 0 || len(message) > MaxMessageBytes {
		return Request{}, fmt.Errorf("%w: invalid request size", ErrProtocol)
	}
	var request Request
	if err := decodeStrictJSON(message, &request); err != nil {
		return Request{}, fmt.Errorf("%w: malformed request", ErrProtocol)
	}
	if request.Version != ProtocolVersion || !validOperation(request.Op) || !validNonce(request.Nonce) {
		return Request{}, fmt.Errorf("%w: invalid request fields", ErrProtocol)
	}
	return request, nil
}

func EncodeRequest(request Request) ([]byte, error) {
	if request.Version != ProtocolVersion || !validOperation(request.Op) || !validNonce(request.Nonce) {
		return nil, fmt.Errorf("%w: invalid request", ErrProtocol)
	}
	return encodeBoundedJSON(request)
}

func SignResponse(key []byte, response *Response) error {
	if response == nil || len(key) != AuthKeyBytes {
		return fmt.Errorf("%w: invalid response signer input", ErrProtocol)
	}
	if err := validateUnsignedResponse(*response); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(responseMACInput(*response))
	response.MAC = hex.EncodeToString(mac.Sum(nil))
	return nil
}

func VerifyResponse(key []byte, request Request, response Response) error {
	if len(key) != AuthKeyBytes || request.Version != ProtocolVersion || !validNonce(request.Nonce) {
		return ErrAuthentication
	}
	if response.Version != ProtocolVersion || response.Nonce != request.Nonce {
		return ErrAuthentication
	}
	if err := validateUnsignedResponse(response); err != nil {
		return ErrAuthentication
	}
	provided, err := hex.DecodeString(response.MAC)
	if err != nil || len(provided) != sha256.Size {
		return ErrAuthentication
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(responseMACInput(response))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return ErrAuthentication
	}
	return nil
}

func DecodeResponse(message []byte) (Response, error) {
	if len(message) == 0 || len(message) > MaxMessageBytes {
		return Response{}, fmt.Errorf("%w: invalid response size", ErrProtocol)
	}
	var response Response
	if err := decodeStrictJSON(message, &response); err != nil {
		return Response{}, fmt.Errorf("%w: malformed response", ErrProtocol)
	}
	return response, nil
}

func EncodeResponse(response Response) ([]byte, error) {
	if err := validateUnsignedResponse(response); err != nil {
		return nil, err
	}
	if len(response.MAC) != sha256.Size*2 {
		return nil, fmt.Errorf("%w: invalid response MAC", ErrProtocol)
	}
	return encodeBoundedJSON(response)
}

func validateUnsignedResponse(response Response) error {
	if response.Version != ProtocolVersion || !validNonce(response.Nonce) {
		return fmt.Errorf("%w: invalid response fields", ErrProtocol)
	}
	if len(response.Token) > MaxTokenBytes || len(response.Error) > MaxErrorBytes ||
		!utf8.ValidString(response.Token) || !utf8.ValidString(response.Error) {
		return fmt.Errorf("%w: response field exceeds bounds", ErrProtocol)
	}
	if response.OK {
		if response.Error != "" {
			return fmt.Errorf("%w: successful response carries an error", ErrProtocol)
		}
	} else if response.Token != "" || response.Error == "" {
		return fmt.Errorf("%w: failure response shape is invalid", ErrProtocol)
	}
	return nil
}

func validOperation(operation string) bool {
	switch operation {
	case OperationToken, OperationRefresh, OperationInvalidate:
		return true
	default:
		return false
	}
}

func validNonce(nonce string) bool {
	if len(nonce) != 64 || strings.ToLower(nonce) != nonce {
		return false
	}
	decoded, err := hex.DecodeString(nonce)
	return err == nil && len(decoded) == 32
}

// responseMACInput uses fixed-width integers and length-prefixed byte strings;
// no two response field sequences can share the same encoded MAC input.
func responseMACInput(response Response) []byte {
	var output bytes.Buffer
	_ = binary.Write(&output, binary.BigEndian, uint32(response.Version))
	if response.OK {
		output.WriteByte(1)
	} else {
		output.WriteByte(0)
	}
	writeLengthPrefixed(&output, response.Nonce)
	writeLengthPrefixed(&output, response.Token)
	writeLengthPrefixed(&output, response.Error)
	return output.Bytes()
}

func writeLengthPrefixed(output *bytes.Buffer, value string) {
	_ = binary.Write(output, binary.BigEndian, uint32(len(value)))
	_, _ = output.WriteString(value)
}

func decodeStrictJSON(message []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(message))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("extra JSON value")
	}
	return nil
}

func encodeBoundedJSON(value any) ([]byte, error) {
	message, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(message) == 0 || len(message) > MaxMessageBytes {
		return nil, fmt.Errorf("%w: encoded message exceeds bounds", ErrProtocol)
	}
	return message, nil
}
